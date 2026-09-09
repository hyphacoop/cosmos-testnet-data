'''
Builds a full validator report for a given calendar month (YYYY-MM),
listing every validator known to the network and, for the specified
period:
- whether it left the active set, and at which blocks it joined/left
- whether it was jailed, and an estimate of when/at which block

Requires an archive API node: the active-set scan and jailed-block
estimation both query historical application state at arbitrary block
heights across the scanned period.

Standalone version: all helper code (from utils and time_to_block) is
inlined below so this file has no dependency on the rest of the
cosmos-tools package.

Arguments:
- rpc endpoint
- api endpoint
- period (YYYY-MM for a full month, or YYYY-MM-DD for a single day)
- output filename (optional)
- checkpoint filename (optional)
- number of worker threads (optional, default 10)
- batch size (optional, default 100)

Outputs a CSV with one row per validator in the network:
- Validator ID (valoper, cosmos, moniker, pubkey, address, cosmosvalcons)
- Current bonded/jailed status
- Whether/when it left and re-joined the active set during the period
- Whether/when it was jailed during the period

Example:
python -m validator_report.validator_report \
    -r <rpc endpoint> \
    -a <api endpoint> \
    -p 2026-08
'''

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
import argparse
import calendar
import requests
import urllib
import base64
import hashlib
import command
import json
import csv
import logging
import os.path
import re
import time

TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
# time_to_block's clip_timestamp() requires a fractional-seconds component
# (it splits on '.' and indexes into the result), so any timestamp handed
# to it must be formatted with one, even if it's all zeros.
RPC_TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.000Z'


# ---------------------------------------------------------------------------
# From utils/utils.py
# ---------------------------------------------------------------------------

def get_status(urlRPC: str):
    endpoint = f"{urlRPC}/status"
    response = requests.get(endpoint).json()["result"]
    return response


def consensus_pubkey_to_bytes_address(pubkey: str):
    """
    Derives the Tendermint validator address (uppercase hex, bytes format)
    directly from a base64-encoded ed25519 consensus pubkey.

    Unlike RPC/CLI validator-set lookups, which only return the current
    live signing set, this works for any validator regardless of bond
    status (jailed, unbonding, unbonded, or never previously seen), since
    the address is just the first 20 bytes of the SHA-256 hash of the
    raw pubkey.
    """
    raw_pubkey = base64.b64decode(pubkey)
    return hashlib.sha256(raw_pubkey).digest()[:20].hex().upper()


def bytes_to_consensus_address(address, binary: str = "gaiad"):
    """
    Converts bytes address to cosmosvalcons format
    """
    p = command.run([binary, "keys", "parse", address])
    res = p.output.split()[10]
    return res.decode("utf-8")


def consensus_address_to_bytes(address, binary: str = "gaiad"):
    """
    Converts cosmosvalcons address to hex bytes format
    """
    p = command.run([binary, "keys", "parse", address, "--output", "json"])
    res = p.output.decode("utf-8")
    res_json = json.loads(res)
    return res_json["bytes"]


def cosmosvaloper_to_cosmos(address, binary: str = "gaiad"):
    """
    Converts bytes address to cosmos format
    """
    bytes_address = consensus_address_to_bytes(address, binary)
    p = command.run([binary, "keys", "parse", bytes_address, "--output", "json"])
    res = p.output.decode("utf-8")
    res_json = json.loads(res)
    return res_json["formats"][0]


def collect_rpc_validators(urlRPC, height: int = 0):
    """
    Collects validators info at the latest block height
    - Address in bytes format
    - pubkey
    - voting power
    - proposer priority
    """
    page = 1
    if height > 0:
        response = requests.get(
            f"{urlRPC}/validators?page={page}&height={height}"
        ).json()["result"]
    else:
        response = requests.get(f"{urlRPC}/validators?page={page}").json()["result"]
    val_count = int(response["count"])
    total = int(response["total"])
    rpc_vals = response["validators"]

    while val_count < total:
        page += 1
        if height > 0:
            response = requests.get(
                f"{urlRPC}/validators?page={page}&height={height}"
            ).json()["result"]
        else:
            response = requests.get(f"{urlRPC}/validators?page={page}").json()["result"]
        val_count += int(response["count"])
        rpc_vals.extend(response["validators"])
    return rpc_vals


def collect_api_validators(urlAPI, height: int = 0):
    """
    Collects the validators info at the specified height
    - operator address in cosmosvaloper format
    - consensus pubkey
    - jailed status
    - tokens
    - delegator shares
    - moniker
    - and more
    """
    if height > 0:
        response = requests.get(
            f"{urlAPI}/cosmos/staking/v1beta1/validators?pagination.limit=1000",
            headers={"x-cosmos-block-height": f"{height}"},
        ).json()
    else:
        response = requests.get(f"{urlAPI}/cosmos/staking/v1beta1/validators").json()
    total = int(response["pagination"]["total"])
    api_vals = response["validators"]
    next_key = response["pagination"]["next_key"]
    while next_key:
        response = requests.get(
            f"{urlAPI}/cosmos/staking/v1beta1/validators?pagination.limit=1000&pagination.key="
            f"{urllib.parse.quote(next_key)}",
            headers={"x-cosmos-block-height": f"{height}"},
        ).json()
        api_vals.extend(response["validators"])
        next_key = response["pagination"]["next_key"]
    return api_vals


def collect_api_validator_set(urlAPI, height: int = 0):
    """
    Collects the validator set at the specified height
    - consensus address in cosmosvalcons format
    - consensus pubkey
    - proposer_priority
    - voting power
    """
    if height > 0:
        response = requests.get(
            f"{urlAPI}/cosmos/base/tendermint/v1beta1/validatorsets/{height}"
        ).json()
    else:
        response = requests.get(
            f"{urlAPI}/cosmos/base/tendermint/v1beta1/validatorsets/latest"
        ).json()
    api_vals = response["validators"]
    total = int(response["pagination"]["total"])
    page = 2
    while len(api_vals) < total:
        if height > 0:
            response = requests.get(
                f"{urlAPI}/cosmos/base/tendermint/v1beta1/validatorsets/{height}?page={page}"
            ).json()
        else:
            response = requests.get(
                f"{urlAPI}/cosmos/base/tendermint/v1beta1/validatorsets/latest?page={page}"
            ).json()
        api_vals.extend(response["validators"])
        page += 1
    return api_vals


def get_slashing_params(urlAPI: str, height: int = 0):
    """
    Returns the info array
    """
    endpoint = f"{urlAPI}/cosmos/slashing/v1beta1/params"
    if height:
        response = requests.get(
            endpoint, headers={"x-cosmos-block-height": f"{height}"}
        ).json()
    else:
        response = requests.get(endpoint).json()
    if "params" in response:
        return response["params"]
    return []


def get_signing_infos(urlAPI: str, height: int = 0):
    """
    Returns the info array
    """
    endpoint = f"{urlAPI}/cosmos/slashing/v1beta1/signing_infos?pagination.limit=1000"
    if height:
        response = requests.get(
            endpoint, headers={"x-cosmos-block-height": f"{height}"}
        ).json()
    else:
        response = requests.get(endpoint).json()
    if "info" in response:
        return response["info"]
    return []


# ---------------------------------------------------------------------------
# From time_to_block/time_to_block.py
# ---------------------------------------------------------------------------

def ttb_get_block(urlRPC, height: int = 0):
    if height > 0:
        response = requests.get(urlRPC + '/block?height=' + str(height)).json()
    else:
        response = requests.get(urlRPC + '/block').json()
    if 'result' not in response:
        print(response)
    return response['result']['block']


def ttb_get_block_timestamp(urlRPC, height: int = 0):
    return ttb_get_block(urlRPC, height)['header']['time']


def ttb_clip_timestamp(timestamp: str):
    clipped_timestamp = timestamp.split('.')
    if len(clipped_timestamp[1]) > 7:
        clipped_timestamp[1] = clipped_timestamp[1][:6] + 'Z'
    return '.'.join(clipped_timestamp)


def ttb_time_difference(ts_newer: str, ts_older: str):
    ts_new = ttb_clip_timestamp(ts_newer)
    ts_old = ttb_clip_timestamp(ts_older)
    dt_new = datetime.strptime(ts_new, '%Y-%m-%dT%H:%M:%S.%fZ')
    dt_old = datetime.strptime(ts_old, '%Y-%m-%dT%H:%M:%S.%fZ')
    time_diff = dt_new - dt_old
    return time_diff.total_seconds()


def ttb_get_block_time(urlRPC, height: int = 0):
    if height == 0:
        height = int(ttb_get_block(urlRPC)['header']['height'])
    reference_ts = ttb_get_block(urlRPC, height)['header']['time']
    minus_one_ts = ttb_get_block(urlRPC, height - 1)['header']['time']
    return ttb_time_difference(reference_ts, minus_one_ts)


def ttb_move(RPC, block, TIME):
    new_timestamp = ttb_get_block_timestamp(RPC, block)
    new_time_delta = ttb_time_difference(new_timestamp, TIME)  # returns negative value if first argument is in the past
    return new_time_delta


def time_to_block(rpc: str, time: str, precision: int, dampener: float):
    # Obtain current block time
    block = int(ttb_get_block(rpc)['header']['height'])
    starting_timestamp = ttb_get_block_timestamp(rpc, block)
    time_delta = ttb_time_difference(starting_timestamp, time)
    while abs(time_delta) > precision:
        # Estimate the block difference: delta / block time = s / (s / block) = blocks
        block_time = ttb_get_block_time(rpc, block)
        block_delta_estimate = int((time_delta / block_time) * dampener)
        if abs(block_delta_estimate) < 1:
            break
        block -= block_delta_estimate
        time_delta = ttb_move(rpc, block, time)
    diff = abs(ttb_time_difference(ttb_get_block_timestamp(rpc, block), time))
    return block, diff


# ---------------------------------------------------------------------------
# Report logic
# ---------------------------------------------------------------------------

def clean_timestamp(timestamp: str) -> datetime:
    '''
    Parses a chain timestamp, discarding any fractional seconds.
    '''
    ts = timestamp
    if '.' in timestamp:
        ts = timestamp.split('.')[0] + 'Z'
    return datetime.strptime(ts, TIME_FORMAT)


def period_bounds(period: str):
    '''
    Returns (start_time, end_time) UTC datetimes spanning the given
    period, from its first second to its last. Accepts either a full
    month (YYYY-MM) or a single day (YYYY-MM-DD).
    '''
    parts = [int(part) for part in period.split('-')]
    year, month = parts[0], parts[1]
    if len(parts) == 3:
        day = parts[2]
        start_time = datetime(year, month, day)
        end_time = datetime(year, month, day, 23, 59, 59)
    else:
        start_time = datetime(year, month, 1)
        last_day = calendar.monthrange(year, month)[1]
        end_time = datetime(year, month, last_day, 23, 59, 59)
    return start_time, end_time


class ValidatorReport():
    def __init__(self, rpc, api, period, output, checkpoint, workers=5, batch_size=50):
        self.rpc = rpc
        self.api = api
        self.period = period
        self.output_file = output
        self.checkpoint_file = checkpoint
        self.workers = workers
        self.batch_size = batch_size

        self.historical_data = {}
        self.previous_valset = []
        self.pubkey_moniker_dict = {}
        self.pubkey_valoper_dict = {}
        self.pubkey_valcons_dict = {}
        self.pubkey_bonded_dict = {}
        self.pubkey_jailed_dict = {}

    # ---- checkpoint I/O, for resuming an interrupted block scan ----

    def read_checkpoint(self):
        '''
        Reads any previously collected scan data, returns True if found.
        '''
        if os.path.isfile(self.checkpoint_file):
            with open(self.checkpoint_file, 'r') as input:
                self.historical_data = json.load(input)
            return True

    def save_checkpoint(self):
        '''
        Saves the active-set scan progress to the checkpoint JSON file.
        '''
        with open(self.checkpoint_file, 'w', encoding='utf-8') as json_file:
            json.dump(self.historical_data, json_file, indent=4)

    # ---- period -> block range resolution ----

    def resolve_window(self):
        '''
        Resolves the YYYY-MM period into a UTC time window and its
        corresponding block range, clipping the end of the window to the
        chain's current time if the period is still in progress.
        '''
        start_time, end_time = period_bounds(self.period)
        status = get_status(self.rpc)
        now = clean_timestamp(status['sync_info']['latest_block_time'])
        if start_time > now:
            raise ValueError(
                f'Period {self.period} has not started yet (chain time: {now}Z)'
            )

        clipped = end_time > now
        if clipped:
            end_time = now

        start_block, _ = time_to_block(
            self.rpc, start_time.strftime(RPC_TIME_FORMAT), precision=8, dampener=0.9
        )
        if clipped:
            end_block = int(status['sync_info']['latest_block_height'])
        else:
            end_block, _ = time_to_block(
                self.rpc, end_time.strftime(RPC_TIME_FORMAT), precision=8, dampener=0.9
            )

        self.start_time = start_time
        self.end_time = end_time
        self.start_block = start_block
        self.end_block = end_block

    # ---- master validator registry ("all validators in the network") ----

    def build_master_registry(self):
        '''
        Builds the full validator roster from the staking module (every
        bond status), keyed by cosmosvaloper address. Every output row
        comes from this registry.
        '''
        api_validators = collect_api_validators(self.api)
        api_validator_set = collect_api_validator_set(self.api)
        valcons_by_pubkey = {
            val['pub_key']['key']: val['address'] for val in api_validator_set
        }

        registry = {}
        for val in api_validators:
            pubkey = val['consensus_pubkey']['key']
            cosmosvaloper = val['operator_address']
            cosmosvalcons = valcons_by_pubkey.get(pubkey)
            bytes_address = consensus_pubkey_to_bytes_address(pubkey)
            if cosmosvalcons is None:
                # The validatorsets endpoint only covers the current active
                # set, so unbonded/unbonding validators won't be in it.
                cosmosvalcons = bytes_to_consensus_address(bytes_address)
            registry[cosmosvaloper] = {
                'cosmosvaloper': cosmosvaloper,
                'cosmos': cosmosvaloper_to_cosmos(cosmosvaloper),
                'moniker': val['description']['moniker'],
                'pubkey': pubkey,
                'address': bytes_address,
                'cosmosvalcons': cosmosvalcons,
                'bonded': val['status'] == 'BOND_STATUS_BONDED',
                'jailed': val['jailed'],
            }
        return registry

    # ---- active-set transition scan (adapted from background_check) ----

    def load_pubkey_dicts(self, height):
        '''
        Builds dicts to map a pubkey to moniker, cosmosvaloper, bonded
        status, jailed status and cosmosvalcons address, at a given height.
        '''
        api_validators = collect_api_validators(self.api, height)
        api_validator_set = collect_api_validator_set(self.api, height)
        self.pubkey_moniker_dict = {
            val['consensus_pubkey']['key']: val['description']['moniker']
            for val in api_validators
        }
        self.pubkey_valoper_dict = {
            val['consensus_pubkey']['key']: val['operator_address']
            for val in api_validators
        }
        self.pubkey_bonded_dict = {
            val['consensus_pubkey']['key']: val['status']
            for val in api_validators
        }
        self.pubkey_jailed_dict = {
            val['consensus_pubkey']['key']: val['jailed']
            for val in api_validators
        }
        self.pubkey_valcons_dict = {
            val['pub_key']['key']: val['address']
            for val in api_validator_set
        }

    def new_transition_entry(self, pubkey, address, height, joined):
        '''
        Builds a fresh transitions-dict entry for a validator, resolving
        its identifying fields from the currently loaded pubkey dicts.
        '''
        cosmosvaloper = self.pubkey_valoper_dict[pubkey]
        cosmosvalcons = self.pubkey_valcons_dict.get(pubkey)
        if cosmosvalcons is None:
            bytes_address = consensus_pubkey_to_bytes_address(pubkey)
            cosmosvalcons = bytes_to_consensus_address(bytes_address)
        return {
            'cosmosvaloper': cosmosvaloper,
            'cosmos': cosmosvaloper_to_cosmos(cosmosvaloper),
            'moniker': self.pubkey_moniker_dict[pubkey],
            'pubkey': pubkey,
            'address': address,
            'cosmosvalcons': cosmosvalcons,
            'bonded': True,
            'joined': joined,
            'left': [],
        }

    def seed_baseline(self):
        '''
        Fetches the active set at start_block and records it as the scan's
        baseline, without recording a 'joined' event for it -- only
        transitions detected after the baseline should count as joining
        or leaving during the period.
        '''
        baseline = collect_rpc_validators(self.rpc, self.start_block)
        self.load_pubkey_dicts(self.start_block)

        transitions = {}
        for val in baseline:
            pubkey = val['pub_key']['value']
            address = val['address']
            if pubkey not in self.pubkey_bonded_dict:
                logging.warning(
                    f'Block {self.start_block}: pubkey {pubkey} (address {address}) '
                    'missing from API validator data, skipping baseline entry'
                )
                continue
            transitions[address] = self.new_transition_entry(pubkey, address, self.start_block, joined=[])

        self.previous_valset = [val['address'] for val in baseline]
        self.historical_data = {
            'period': self.period,
            'start_block': self.start_block,
            'end_block': self.end_block,
            'last_block': self.start_block,
            'previous_valset': self.previous_valset,
            'transitions': transitions,
        }

    def update_transitions(self, rpc_data, height: int):
        '''
        - Records newly seen validators (mid-period entrants)
        - Records validators leaving the active set
        - Records validators re-joining the active set
        '''
        self.load_pubkey_dicts(height)
        current_addresses = {val['address'] for val in rpc_data}
        pubkey_by_address = {val['address']: val['pub_key']['value'] for val in rpc_data}
        transitions = self.historical_data['transitions']

        for address in current_addresses:
            if address in transitions:
                continue
            pubkey = pubkey_by_address[address]
            if pubkey not in self.pubkey_bonded_dict:
                logging.warning(
                    f'Block {height}: pubkey {pubkey} (address {address}) missing from '
                    'API validator data, skipping for this block'
                )
                continue
            transitions[address] = self.new_transition_entry(pubkey, address, height, joined=[height])

        for val in transitions.values():
            pubkey = val['pubkey']
            if pubkey not in self.pubkey_bonded_dict:
                logging.warning(
                    f'Block {height}: pubkey {pubkey} (moniker {val["moniker"]}) missing '
                    'from API validator data, keeping its previous bonded status'
                )
                continue
            bonded = self.pubkey_bonded_dict[pubkey] == 'BOND_STATUS_BONDED'
            address = val['address']
            if address not in current_addresses:
                if val['bonded'] and not bonded:
                    val['left'].append(height)
            else:
                if not val['bonded'] and bonded:
                    val['joined'].append(height)
            val['bonded'] = bonded

    def fetch_rpc_validators_with_retry(self, height, retries=5, backoff=1.0):
        '''
        Fetches the RPC validator set for a single height, retrying with
        exponential backoff if the node drops/resets the connection under
        concurrent load.
        '''
        for attempt in range(retries):
            try:
                return collect_rpc_validators(self.rpc, height)
            except (requests.exceptions.RequestException, KeyError) as error:
                if attempt == retries - 1:
                    raise
                wait = backoff * (2 ** attempt)
                logging.warning(
                    f'Block {height}: fetch failed ({error}), '
                    f'retrying in {wait:.1f}s (attempt {attempt + 1}/{retries})'
                )
                time.sleep(wait)

    def prefetch_rpc_validators(self, heights):
        '''
        Fetches the RPC validator set for a batch of heights concurrently.
        Returns a dict mapping height -> rpc validator data.
        '''
        results = {}
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            future_to_height = {
                executor.submit(self.fetch_rpc_validators_with_retry, height): height
                for height in heights
            }
            for future in as_completed(future_to_height):
                height = future_to_height[future]
                results[height] = future.result()
        return results

    def check_valset(self, height: int, rpc_validators):
        '''
        If the active set at this height differs from the previous one,
        update the tracked transitions.
        '''
        valset_addresses = [val['address'] for val in rpc_validators]
        if valset_addresses != self.previous_valset:
            self.update_transitions(rpc_validators, height)
            self.previous_valset = valset_addresses
        self.historical_data['last_block'] = height

    def scan_active_set(self):
        '''
        Scans the [start_block, end_block] range, resuming from a
        checkpoint when one matches this exact period/block range.
        '''
        resumed = (
            self.read_checkpoint()
            and self.historical_data.get('start_block') == self.start_block
            and self.historical_data.get('end_block') == self.end_block
        )
        if resumed:
            self.previous_valset = self.historical_data.get('previous_valset', [])
            range_start = self.historical_data['last_block'] + 1
            logging.info(f'Resuming active-set scan from block {range_start}')
        else:
            logging.info(f'Seeding active-set baseline at block {self.start_block}')
            self.seed_baseline()
            range_start = self.start_block + 1

        heights = list(range(range_start, self.end_block + 1))
        for batch_start in range(0, len(heights), self.batch_size):
            batch = heights[batch_start:batch_start + self.batch_size]
            logging.info(f'Fetching blocks {batch[0]}-{batch[-1]} with {self.workers} workers')
            prefetched = self.prefetch_rpc_validators(batch)
            for height in batch:
                self.check_valset(height, prefetched[height])
            self.historical_data['previous_valset'] = self.previous_valset
            self.save_checkpoint()
        self.save_checkpoint()

    # ---- jailing detection (adapted from last_jailed_recorder) ----

    def scan_jailing(self):
        '''
        Returns a dict keyed by cosmosvalcons address, of validators whose
        jailing (or, for tombstoned validators, whose tombstoning) is
        estimated to fall within the period.
        '''
        slashing_params = get_slashing_params(self.api)
        jail_duration = float(slashing_params['downtime_jail_duration'].split('s')[0])
        signing_infos = get_signing_infos(self.api)

        jailing = {}
        for info in signing_infos:
            jailed_until = info.get('jailed_until')
            if not jailed_until:
                continue
            consensus_address = info['address']

            if info.get('tombstoned'):
                # A tombstone is a permanent jail: jailed_until minus the
                # (downtime-only) jail duration means nothing here. Record
                # it as a candidate; the merge step confirms it happened
                # in-window using the active-set scan's 'left' heights.
                jailing[consensus_address] = {
                    'jailed_reason': 'tombstone',
                    'jailed_time': None,
                }
                continue

            jailed_until_time = clean_timestamp(jailed_until)
            jailed_time = jailed_until_time - timedelta(seconds=jail_duration)
            if self.start_time <= jailed_time <= self.end_time:
                jailing[consensus_address] = {
                    'jailed_reason': 'downtime',
                    'jailed_time': jailed_time,
                }
        return jailing

    def estimate_jailed_block(self, consensus_address: str, jailed_time: datetime):
        '''
        Fallback for validators not captured by the active-set scan (e.g.
        jailed while already outside the tracked range): estimates the
        block via time_to_block, then scans a narrow window around it for
        the last block where the validator was still in the active set.
        '''
        jailed_time_str = jailed_time.strftime(RPC_TIME_FORMAT)
        estimated_block, _ = time_to_block(self.rpc, jailed_time_str, precision=8, dampener=0.9)
        last_block = estimated_block
        for block in range(estimated_block - 10, estimated_block + 10):
            valset = collect_api_validator_set(self.api, block)
            addresses = [val['address'] for val in valset]
            if consensus_address not in addresses:
                return last_block
            last_block = block
        return last_block

    # ---- merge + output ----

    def build(self):
        self.resolve_window()
        logging.info(
            f'Period {self.period}: {self.start_time}Z - {self.end_time}Z, '
            f'blocks {self.start_block}-{self.end_block}'
        )

        registry = self.build_master_registry()
        self.scan_active_set()
        jailing = self.scan_jailing()
        transitions = self.historical_data['transitions']

        rows = []
        for val in registry.values():
            transition = transitions.get(val['address'])
            left_heights = transition['left'] if transition else []
            joined_heights = transition['joined'] if transition else []

            jailed_during_period = False
            jailed_time = ''
            jailed_block = ''
            jailed_reason = ''

            jail_info = jailing.get(val['cosmosvalcons'])
            if jail_info:
                jailed_reason = jail_info['jailed_reason']
                if jailed_reason == 'tombstone':
                    if left_heights:
                        jailed_during_period = True
                        jailed_block = left_heights[-1] - 1
                    else:
                        # No in-window evidence of leaving the set: can't
                        # confirm the tombstoning happened during this
                        # period, so don't report it as such.
                        jailed_reason = ''
                else:
                    jailed_during_period = True
                    jailed_time = jail_info['jailed_time'].strftime(TIME_FORMAT)
                    if left_heights:
                        jailed_block = left_heights[-1] - 1
                    else:
                        jailed_block = self.estimate_jailed_block(
                            val['cosmosvalcons'], jail_info['jailed_time']
                        )

            rows.append({
                'cosmosvaloper': val['cosmosvaloper'],
                'cosmos': val['cosmos'],
                'moniker': val['moniker'],
                'pubkey': val['pubkey'],
                'address': val['address'],
                'cosmosvalcons': val['cosmosvalcons'],
                'bonded': val['bonded'],
                'jailed': val['jailed'],
                'left_active_set': bool(left_heights),
                'left_heights': '|'.join(str(h) for h in left_heights),
                'joined_active_set': bool(joined_heights),
                'joined_heights': '|'.join(str(h) for h in joined_heights),
                'jailed_during_period': jailed_during_period,
                'jailed_time': jailed_time,
                'jailed_block': jailed_block,
                'jailed_reason': jailed_reason,
            })

        self.save_csv(rows)

    def save_csv(self, rows):
        fieldnames = [
            'cosmosvaloper',
            'cosmos',
            'moniker',
            'pubkey',
            'address',
            'cosmosvalcons',
            'bonded',
            'jailed',
            'left_active_set',
            'left_heights',
            'joined_active_set',
            'joined_heights',
            'jailed_during_period',
            'jailed_time',
            'jailed_block',
            'jailed_reason',
        ]
        with open(self.output_file, 'w', encoding='utf-8') as output:
            output.writelines([
                f'Period {self.period}, blocks {self.start_block}-{self.end_block}\n'
            ])
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        logging.info(f'Saved {len(rows)} validators to {self.output_file}')


logging.basicConfig(
    filename=None,
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)

def period_type(value):
    if not re.fullmatch(r'\d{4}-(0[1-9]|1[0-2])(-(0[1-9]|[12]\d|3[01]))?', value):
        raise argparse.ArgumentTypeError(f"'{value}' is not in YYYY-MM or YYYY-MM-DD format")
    return value


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Build a per-period report of every validator in the network: '
                     'whether it left the active set and whether it was jailed.'
    )
    parser.add_argument('-r', '--rpc', type=str, required=True, help='RPC node address, including port')
    parser.add_argument('-a', '--api', type=str, required=True, help='API node address, including port')
    parser.add_argument('-p', '--period', type=period_type, required=True, help='Period to check: YYYY-MM for a full month, or YYYY-MM-DD for a single day')
    parser.add_argument('-o', '--output', type=str, help='Filename to save the validator report to (default: validator_report.<period>.csv)')
    parser.add_argument('-i', '--input', type=str, help='Checkpoint JSON filename to resume an interrupted scan (default: validator_report.<period>.json)')
    parser.add_argument('-w', '--workers', type=int, default=10, help='Number of concurrent worker threads for RPC fetches')
    parser.add_argument('-b', '--batch-size', type=int, default=100, help='Number of blocks to fetch concurrently per batch')

    args = parser.parse_args()

    output_file = args.output or f'validator_report.{args.period}.csv'
    checkpoint_file = args.input or f'validator_report.{args.period}.json'

    report = ValidatorReport(
        args.rpc, args.api, args.period, output_file, checkpoint_file, args.workers, args.batch_size
    )
    report.build()
