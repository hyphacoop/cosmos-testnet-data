#!/usr/bin/env python3
'''
Builds a validator jailing report for a given calendar month (YYYY-MM),
listing every validator that was jailed at some point during the period,
along with when and why.

A validator can be jailed for exactly three reasons, and each is detected
differently:
- Downtime (missing too many blocks): detected via a `block_search` query for
  the slashing module's `slash{reason='missing_signature'}` event.
- Double-signing (equivocation): always jails *and* tombstones the validator
  permanently; detected via `block_search` for `slash{reason='double_sign'}`.
- Self-delegation dropping below the validator's minimum: the staking module
  jails the validator with no dedicated event, so this is detected by finding
  `MsgUndelegate` transactions where the delegator is the validator's own
  account (via `tx_search`), then confirming the validator's jailed status
  flipped at that block.

Both `slash` events above are emitted in BeginBlock, not inside a transaction,
so they are only visible through CometBFT's `block_search` RPC method (which
indexes FinalizeBlock events: begin+end+tx) -- never through `tx_search`
(which only sees tx-execution events).

Requires the RPC endpoint to have tx/block indexing enabled
(`config.toml`'s `[tx_index] indexer = "kv"`) and an `index-events` setting
(`app.toml`) that doesn't exclude `slash.*`/`message.action` -- not guaranteed
on an arbitrary public endpoint. If indexed search isn't available, this
script falls back to a `signing_infos`-based snapshot, which can only recover
downtime jailings (not self-delegation jailings, and not the timing of
tombstonings) -- see `detect_via_signing_infos_fallback`.

Arguments:
- rpc endpoint
- api endpoint
- period (YYYY-MM)
- output filename (optional)
- number of worker threads for self-delegation confirmation (optional, default 5)

Outputs a CSV with one row per validator jailed during the period (validators
never jailed in the period are omitted entirely):
- Validator ID (valoper, cosmos, moniker, pubkey, address, cosmosvalcons)
- When/why it was jailed (block, time, reason, whether it was tombstoned)

Standalone: the only third-party dependency is `requests` (Python 3.9+).

Example:
python validator_report.py \
    -r <rpc endpoint> \
    -a <api endpoint> \
    -p 2026-08
'''

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
import argparse
import base64
import binascii
import calendar
import csv
import hashlib
import logging

import requests

TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
REQUEST_TIMEOUT = 60


# ---- timestamps ----

def parse_timestamp(timestamp: str) -> datetime:
    '''
    Parses an RFC 3339 chain timestamp into a naive UTC datetime. CometBFT
    emits up to nanosecond precision (and omits the fraction entirely when
    it's zero), so the fraction is optional and truncated to microseconds.
    '''
    base, _, fraction = timestamp.rstrip('Z').partition('.')
    parsed = datetime.strptime(base, '%Y-%m-%dT%H:%M:%S')
    if fraction:
        parsed = parsed.replace(microsecond=int(fraction[:6].ljust(6, '0')))
    return parsed


def clean_timestamp(timestamp: str) -> datetime:
    '''
    Parses a chain timestamp, discarding any fractional seconds.
    '''
    return parse_timestamp(timestamp).replace(microsecond=0)


# ---- bech32 address conversion (BIP-173) ----

BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'


def _bech32_polymod(values):
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = (checksum & 0x1ffffff) << 5 ^ value
        for i in range(5):
            checksum ^= generator[i] if (top >> i) & 1 else 0
    return checksum


def _bech32_hrp_expand(hrp: str):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convert_bits(data, from_bits: int, to_bits: int, pad: bool):
    acc = 0
    bits = 0
    result = []
    max_value = (1 << to_bits) - 1
    for value in data:
        acc = (acc << from_bits) | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            result.append((acc >> bits) & max_value)
    if pad and bits:
        result.append((acc << (to_bits - bits)) & max_value)
    return result


def bech32_encode(hrp: str, data: bytes) -> str:
    values = _convert_bits(data, 8, 5, pad=True)
    polymod = _bech32_polymod(_bech32_hrp_expand(hrp) + values + [0] * 6) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + '1' + ''.join(BECH32_CHARSET[v] for v in values + checksum)


def bech32_decode(address: str):
    '''
    Returns (hrp, data bytes) for a bech32 address.
    '''
    hrp, _, encoded = address.lower().rpartition('1')
    if not hrp or len(encoded) < 6 or any(c not in BECH32_CHARSET for c in encoded):
        raise ValueError(f'Invalid bech32 address: {address}')
    values = [BECH32_CHARSET.index(c) for c in encoded]
    if _bech32_polymod(_bech32_hrp_expand(hrp) + values) != 1:
        raise ValueError(f'Invalid bech32 checksum: {address}')
    return hrp, bytes(_convert_bits(values[:-6], 5, 8, pad=False))


def cosmosvaloper_to_cosmos(cosmosvaloper: str) -> str:
    '''
    Converts an operator address to its account address (same bytes,
    e.g. cosmosvaloper... -> cosmos...).
    '''
    hrp, data = bech32_decode(cosmosvaloper)
    return bech32_encode(hrp.removesuffix('valoper'), data)


def consensus_pubkey_to_bytes_address(pubkey: str) -> str:
    '''
    Derives the CometBFT validator address (uppercase hex) from a
    base64-encoded ed25519 consensus pubkey: the first 20 bytes of the
    SHA-256 hash of the raw pubkey. Works for any validator regardless of
    bond status.
    '''
    return hashlib.sha256(base64.b64decode(pubkey)).digest()[:20].hex().upper()


def bytes_to_consensus_address(bytes_address: str, cosmosvaloper: str) -> str:
    '''
    Converts a hex validator address to cosmosvalcons format, taking the
    chain's bech32 prefix from the validator's operator address.
    '''
    hrp, _ = bech32_decode(cosmosvaloper)
    return bech32_encode(hrp.removesuffix('valoper') + 'valcons', bytes.fromhex(bytes_address))


# ---- RPC queries ----

def rpc_call(rpc: str, method: str, params: dict) -> dict:
    '''
    Issues a JSON-RPC request and returns the full response, including any
    'error' key.
    '''
    return requests.post(
        rpc,
        json={'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params},
        timeout=REQUEST_TIMEOUT,
    ).json()


def rpc_search(rpc: str, method: str, query: str, per_page: int = 100):
    '''
    Runs a paginated tx_search or block_search query and returns every hit.
    Returns None (not []) if the endpoint rejects the query outright, so
    callers can distinguish "indexing unavailable" from "zero matches".
    '''
    result_key = 'txs' if method == 'tx_search' else 'blocks'
    hits = []
    page = 1
    while True:
        response = rpc_call(rpc, method, {'query': query, 'page': str(page), 'per_page': str(per_page)})
        if 'error' in response:
            if page == 1:
                logging.warning(f"{method} unavailable ({response['error']})")
                return None
            logging.warning(f"{method} failed on page {page} ({response['error']}), results are incomplete")
            return hits
        result = response.get('result', {})
        total = int(result.get('total_count') or 0)
        page_hits = result.get(result_key) or []
        hits.extend(page_hits)
        if len(hits) >= total or not page_hits:
            return hits
        page += 1


def get_status(rpc: str) -> dict:
    return requests.get(f'{rpc}/status', timeout=REQUEST_TIMEOUT).json()['result']


def get_block(rpc: str, height: int = 0) -> dict:
    params = {'height': height} if height > 0 else {}
    response = requests.get(f'{rpc}/block', params=params, timeout=REQUEST_TIMEOUT).json()
    return response['result']['block']


def get_block_timestamp(rpc: str, height: int = 0) -> str:
    return get_block(rpc, height)['header']['time']


def get_block_results(rpc: str, height: int) -> dict:
    response = requests.get(f'{rpc}/block_results', params={'height': height}, timeout=REQUEST_TIMEOUT).json()
    return response.get('result', {})


def time_to_block(rpc: str, target: datetime, precision: int = 8, dampener: float = 0.9) -> int:
    '''
    Finds the block closest to the target time: starting from the latest
    block, repeatedly estimates the block distance from the local block time
    and jumps there, until within `precision` seconds.
    '''
    block = int(get_block(rpc)['header']['height'])
    time_delta = (parse_timestamp(get_block_timestamp(rpc, block)) - target).total_seconds()
    while abs(time_delta) > precision:
        block_time = (
            parse_timestamp(get_block_timestamp(rpc, block))
            - parse_timestamp(get_block_timestamp(rpc, block - 1))
        ).total_seconds()
        block_delta_estimate = int((time_delta / block_time) * dampener)
        if abs(block_delta_estimate) < 1:
            break
        block -= block_delta_estimate
        time_delta = (parse_timestamp(get_block_timestamp(rpc, block)) - target).total_seconds()
    return block


# ---- API queries ----

def api_get(api: str, path: str, height: int = 0, params: dict = None) -> dict:
    headers = {'x-cosmos-block-height': str(height)} if height else {}
    return requests.get(f'{api}{path}', params=params, headers=headers, timeout=REQUEST_TIMEOUT).json()


def collect_api_validators(api: str) -> list:
    '''
    Collects every validator in the staking module, across all bond statuses.
    '''
    validators = []
    next_key = None
    while True:
        params = {'pagination.limit': 1000}
        if next_key:
            params['pagination.key'] = next_key
        response = api_get(api, '/cosmos/staking/v1beta1/validators', params=params)
        validators.extend(response['validators'])
        next_key = response['pagination']['next_key']
        if not next_key:
            return validators


def collect_api_validator_set(api: str, height: int = 0) -> list:
    '''
    Collects the active validator set (cosmosvalcons addresses, pubkeys,
    voting power) at the given height, or the latest if 0.
    '''
    path = f"/cosmos/base/tendermint/v1beta1/validatorsets/{height if height > 0 else 'latest'}"
    validators = []
    while True:
        # CometBFT caps validator pages at 100 regardless of the limit requested.
        response = api_get(api, path, params={'pagination.limit': 100, 'pagination.offset': len(validators)})
        page = response['validators']
        validators.extend(page)
        if len(validators) >= int(response['pagination']['total']) or not page:
            return validators


def get_validator(api: str, cosmosvaloper: str, height: int = 0) -> dict:
    '''
    Fetches a single validator by operator address, optionally at a
    historical height. Returns {} if it can't be found at that height.
    '''
    return api_get(api, f'/cosmos/staking/v1beta1/validators/{cosmosvaloper}', height).get('validator', {})


def get_slashing_params(api: str) -> dict:
    return api_get(api, '/cosmos/slashing/v1beta1/params').get('params', {})


def get_signing_infos(api: str) -> list:
    return api_get(api, '/cosmos/slashing/v1beta1/signing_infos', params={'pagination.limit': 1000}).get('info', [])


def period_bounds(period: str):
    '''
    Returns (start_time, end_time) UTC datetimes spanning the given
    YYYY-MM period, from its first second to its last.
    '''
    year, month = (int(part) for part in period.split('-'))
    start_time = datetime(year, month, 1)
    last_day = calendar.monthrange(year, month)[1]
    end_time = datetime(year, month, last_day, 23, 59, 59)
    return start_time, end_time


def _maybe_b64decode(value):
    '''
    Attribute keys/values in ABCI events are base64-encoded on some
    CometBFT/SDK versions and plain UTF-8 on others. Decodes if the value
    looks like valid base64, otherwise returns it unchanged.
    '''
    if not isinstance(value, str):
        return value
    try:
        return base64.b64decode(value, validate=True).decode('utf-8')
    except (binascii.Error, ValueError):
        return value


def decode_event(event) -> dict:
    '''
    Decodes an ABCI event's attributes into a plain {key: value} dict.
    '''
    return {
        _maybe_b64decode(attribute.get('key', '')): _maybe_b64decode(attribute.get('value', ''))
        for attribute in event.get('attributes', [])
    }


def find_slash_event(block_results: dict, reason: str):
    '''
    Looks for a 'slash' event with the given 'reason' attribute across a
    block_results response, checking every event-list key ABCI has used
    across SDK/CometBFT versions (begin/end-block events pre-ABCI 2.0,
    finalize-block events since). Returns the decoded attribute dict, or
    None if no matching event is found.
    '''
    for section in ('finalize_block_events', 'begin_block_events', 'end_block_events'):
        for event in block_results.get(section) or []:
            if event.get('type') != 'slash':
                continue
            decoded = decode_event(event)
            if decoded.get('reason') == reason:
                return decoded
    return None


def self_undelegation_validator(tx: dict, valoper_by_cosmos: dict):
    '''
    If this MsgUndelegate tx is a validator undelegating from its own
    account, returns its cosmosvaloper address; otherwise None.

    Cross-checks the 'unbond' event's 'delegator' attribute (present on some
    SDK versions) against the 'message' event's 'sender' attribute (always
    emitted for every Msg), since attribute sets on 'unbond' vary by version.
    '''
    sender = None
    validator_addr = None
    delegator_addr = None
    for event in tx.get('tx_result', {}).get('events', []):
        etype = event.get('type')
        if etype == 'message':
            decoded = decode_event(event)
            if decoded.get('action', '').endswith('MsgUndelegate'):
                sender = decoded.get('sender') or sender
        elif etype == 'unbond':
            decoded = decode_event(event)
            validator_addr = decoded.get('validator') or validator_addr
            delegator_addr = decoded.get('delegator') or delegator_addr

    delegator = delegator_addr or sender
    if not validator_addr or not delegator:
        return None
    if valoper_by_cosmos.get(delegator) == validator_addr:
        return validator_addr
    return None


class ValidatorReport():
    def __init__(self, rpc, api, period, output, workers=5):
        self.rpc = rpc
        self.api = api
        self.period = period
        self.output_file = output
        self.workers = workers

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

        start_block = time_to_block(self.rpc, start_time)
        if clipped:
            end_block = int(status['sync_info']['latest_block_height'])
        else:
            end_block = time_to_block(self.rpc, end_time)

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
        registry = {}
        for val in collect_api_validators(self.api):
            pubkey = val['consensus_pubkey']['key']
            cosmosvaloper = val['operator_address']
            # Derived from the pubkey rather than looked up in the
            # validatorsets endpoint, which only covers the active set.
            bytes_address = consensus_pubkey_to_bytes_address(pubkey)
            registry[cosmosvaloper] = {
                'cosmosvaloper': cosmosvaloper,
                'cosmos': cosmosvaloper_to_cosmos(cosmosvaloper),
                'moniker': val['description']['moniker'],
                'pubkey': pubkey,
                'address': bytes_address,
                'cosmosvalcons': bytes_to_consensus_address(bytes_address, cosmosvaloper),
                'bonded': val['status'] == 'BOND_STATUS_BONDED',
                'jailed': val['jailed'],
            }
        return registry

    # ---- primary jailing detection, via indexed block/tx search ----

    def estimate_jailed_block(self, consensus_address: str, jailed_time: datetime):
        '''
        Estimates the jailing block via time_to_block, then scans a narrow
        window around it for the last block where the validator was still
        in the active set. Only used by the signing_infos fallback path --
        the block_search path already gets an exact height from its hits.
        '''
        estimated_block = time_to_block(self.rpc, jailed_time)
        last_block = estimated_block
        for block in range(estimated_block - 10, estimated_block + 10):
            valset = collect_api_validator_set(self.api, block)
            addresses = [val['address'] for val in valset]
            if consensus_address not in addresses:
                return last_block
            last_block = block
        return last_block

    def _detect_slash_jailings(self, reason: str, jailed_reason: str, tombstoned: bool):
        '''
        Queries block_search for slash{reason=<reason>} events in the
        resolved block range. Returns None (not {}) if the endpoint can't
        answer the query at all, so callers can distinguish "indexing
        unavailable" from "zero matches, genuinely nothing happened".
        '''
        query = (
            f"slash.reason='{reason}' "
            f"AND block.height>={self.start_block} AND block.height<={self.end_block}"
        )
        hits = rpc_search(self.rpc, 'block_search', query)
        if hits is None:
            logging.warning('This endpoint likely lacks tx/block indexing support')
            return None

        results = {}
        for hit in hits:
            height = int(hit['block']['header']['height'])
            block_results = get_block_results(self.rpc, height)
            event = find_slash_event(block_results, reason)
            if not event:
                logging.warning(
                    f'Block {height}: matched a {reason} slash search hit but found no '
                    'matching slash event in block_results'
                )
                continue
            cons_addr = event.get('jailed') or event.get('address')
            if not cons_addr:
                continue
            jailed_time = clean_timestamp(get_block_timestamp(self.rpc, height))
            results[cons_addr] = {
                'jailed_block': height,
                'jailed_time': jailed_time.strftime(TIME_FORMAT),
                'jailed_reason': jailed_reason,
                'tombstoned': tombstoned,
                'burned_coins': event.get('burned_coins', ''),
            }
        return results

    def detect_downtime_jailings(self):
        return self._detect_slash_jailings('missing_signature', 'downtime', tombstoned=False)

    def detect_doublesign_jailings(self):
        return self._detect_slash_jailings('double_sign', 'double_sign', tombstoned=True)

    def confirm_selfdelegation_jailing(self, cosmosvaloper: str, height: int) -> bool:
        '''
        Confirms whether a candidate self-undelegation tx actually crossed
        MinSelfDelegation and triggered jailing, by checking whether the
        validator's jailed flag flipped false->true across this height.
        '''
        before = get_validator(self.api, cosmosvaloper, height - 1)
        after = get_validator(self.api, cosmosvaloper, height)
        return bool(before) and bool(after) and not before.get('jailed') and after.get('jailed')

    def detect_selfdelegation_jailings(self, registry: dict):
        '''
        MsgUndelegate never emits a jailing-specific event, so this is a
        filter-then-confirm search: find self-undelegation txs via
        tx_search, then confirm each candidate actually triggered jailing.
        '''
        query = (
            f"message.action='/cosmos.staking.v1beta1.MsgUndelegate' "
            f"AND tx.height>={self.start_block} AND tx.height<={self.end_block}"
        )
        txs = rpc_search(self.rpc, 'tx_search', query)
        if not txs:
            logging.info(
                'No MsgUndelegate transactions found for this period via tx_search '
                '(if self-undelegations are known to have occurred, verify tx indexing is enabled)'
            )
            return {}

        valoper_by_cosmos = {v['cosmos']: v['cosmosvaloper'] for v in registry.values()}
        valcons_by_valoper = {v['cosmosvaloper']: v['cosmosvalcons'] for v in registry.values()}

        candidates = []
        for tx in txs:
            valoper = self_undelegation_validator(tx, valoper_by_cosmos)
            if valoper:
                candidates.append((valoper, int(tx['height'])))
        if not candidates:
            return {}

        logging.info(f'Confirming jailing status for {len(candidates)} self-undelegation candidate(s)')
        results = {}
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = {
                executor.submit(self.confirm_selfdelegation_jailing, valoper, height): (valoper, height)
                for valoper, height in candidates
            }
            for future in as_completed(futures):
                valoper, height = futures[future]
                if not future.result():
                    continue
                cons_addr = valcons_by_valoper.get(valoper)
                if not cons_addr:
                    continue
                jailed_time = clean_timestamp(get_block_timestamp(self.rpc, height))
                results[cons_addr] = {
                    'jailed_block': height,
                    'jailed_time': jailed_time.strftime(TIME_FORMAT),
                    'jailed_reason': 'low_self_delegation',
                    'tombstoned': False,
                    'burned_coins': '',
                }
        return results

    # ---- fallback jailing detection, for endpoints without indexed search ----

    def detect_via_signing_infos_fallback(self):
        '''
        Fallback for endpoints without block_search support. Only recovers
        downtime jailings: JailedUntil is set to (jail time + downtime jail
        duration), so it can be inverted. Double-sign/tombstone jailings are
        NOT recoverable here -- JailedUntil for a tombstoned validator is a
        fixed far-future constant unrelated to when the tombstoning
        happened, so there's no way to confirm it fell within the period.
        Self-delegation jailings are entirely invisible in this mode (see
        module docstring).
        '''
        slashing_params = get_slashing_params(self.api)
        jail_duration = float(slashing_params['downtime_jail_duration'].split('s')[0])
        signing_infos = get_signing_infos(self.api)

        downtime = {}
        for info in signing_infos:
            if info.get('tombstoned'):
                continue
            jailed_until = info.get('jailed_until')
            if not jailed_until:
                continue
            jailed_until_time = clean_timestamp(jailed_until)
            jailed_time = jailed_until_time - timedelta(seconds=jail_duration)
            if not (self.start_time <= jailed_time <= self.end_time):
                continue
            cons_addr = info['address']
            jailed_block = self.estimate_jailed_block(cons_addr, jailed_time)
            downtime[cons_addr] = {
                'jailed_block': jailed_block,
                'jailed_time': jailed_time.strftime(TIME_FORMAT),
                'jailed_reason': 'downtime',
                'tombstoned': False,
                'burned_coins': '',
            }
        return downtime

    # ---- merge + output ----

    def build(self):
        self.resolve_window()
        logging.info(
            f'Period {self.period}: {self.start_time}Z - {self.end_time}Z, '
            f'blocks {self.start_block}-{self.end_block}'
        )

        registry = self.build_master_registry()

        downtime = self.detect_downtime_jailings()
        doublesign = self.detect_doublesign_jailings()
        if downtime is None or doublesign is None:
            logging.warning(
                'Indexed block_search unavailable on this endpoint; falling back to '
                'signing_infos-based detection. This can only recover downtime jailings '
                'still reflected in current signing info -- double-sign/tombstone timing '
                'and low_self_delegation jailings CANNOT be detected in this mode.'
            )
            downtime = self.detect_via_signing_infos_fallback()
            doublesign = {}
            selfdeleg = {}
            detection_method = 'signing_infos_fallback'
        else:
            selfdeleg = self.detect_selfdelegation_jailings(registry)
            detection_method = 'block_search'

        jailings = {}
        for source in (downtime, doublesign, selfdeleg):
            for cons_addr, info in source.items():
                existing = jailings.get(cons_addr)
                if existing and existing['jailed_block'] and info['jailed_block']:
                    if info['jailed_block'] <= existing['jailed_block']:
                        logging.warning(
                            f'{cons_addr}: multiple jailing events detected in period, '
                            'keeping the latest by block'
                        )
                        continue
                jailings[cons_addr] = info

        val_by_cosmosvalcons = {val['cosmosvalcons']: val for val in registry.values()}

        rows = []
        for cons_addr, jail_info in jailings.items():
            val = val_by_cosmosvalcons.get(cons_addr)
            if val is None:
                logging.warning(
                    f'{cons_addr}: jailed during period but not found in the current '
                    'validator registry, skipping row'
                )
                continue
            rows.append({
                'cosmosvaloper': val['cosmosvaloper'],
                'cosmos': val['cosmos'],
                'moniker': val['moniker'],
                'pubkey': val['pubkey'],
                'address': val['address'],
                'cosmosvalcons': val['cosmosvalcons'],
                'jailed_block': jail_info.get('jailed_block', ''),
                'jailed_time': jail_info.get('jailed_time', ''),
                'jailed_reason': jail_info.get('jailed_reason', ''),
                'tombstoned': jail_info.get('tombstoned', False),
                'burned_coins': jail_info.get('burned_coins', ''),
                'detection_method': detection_method,
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
            'jailed_block',
            'jailed_time',
            'jailed_reason',
            'tombstoned',
            'burned_coins',
            'detection_method',
        ]
        with open(self.output_file, 'w', encoding='utf-8') as output:
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

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Build a per-period report of every validator in the network: '
                     'whether/when/why it was jailed.'
    )
    parser.add_argument('-r', '--rpc', type=str, required=True, help='RPC node address, including port')
    parser.add_argument('-a', '--api', type=str, required=True, help='API node address, including port')
    parser.add_argument('-p', '--period', type=str, required=True, help='Period to check, in YYYY-MM format')
    parser.add_argument('-o', '--output', type=str, help='Filename to save the validator report to (default: validator_report.<period>.csv)')
    parser.add_argument('-w', '--workers', type=int, default=5, help='Number of concurrent worker threads for self-delegation confirmation checks')

    args = parser.parse_args()

    output_file = args.output or f'validator_report.{args.period}.csv'

    report = ValidatorReport(args.rpc, args.api, args.period, output_file, args.workers)
    report.build()
