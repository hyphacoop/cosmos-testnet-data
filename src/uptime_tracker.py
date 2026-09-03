"""
Saves a CSV with the validator uptimes for provider and cosmoshub-4

Standalone version: all helper code (from utils, time_to_block,
signature_counter, address_book) is inlined below so this file has no
dependency on the rest of the cosmos-tools package.

Example:
python -m tip.uptime_tracker -m 2026-07
"""

import json
import csv
import argparse
import logging
import re
import os.path
import base64
import hashlib
import urllib
import requests
import command
from datetime import datetime


logging.basicConfig(
    filename=None,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# ---------------------------------------------------------------------------
# From utils/utils.py
# ---------------------------------------------------------------------------

def get_chain_id(urlRPC: str):
    """
    Returns the chain id from the RPC endpoint.
    """
    response = requests.get(f"{urlRPC}/status").json()
    return response["result"]["node_info"]["network"]


def get_block(urlRPC, height: int = 0):
    if height > 0:
        response = requests.get(urlRPC + "/block?height=" + str(height)).json()
    else:
        response = requests.get(urlRPC + "/block").json()
    return response["result"]["block"]


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


def signatures_bytes_addrs(urlRPC, block: int = 1):
    """
    Returns a list of the last commit's signatures for a given block
    in bytes format.
    """
    if block > 1:
        # Use a 5s timeout to avoid hanging if the node is unresponsive
        res = requests.get(f"{urlRPC}/commit?height={block}", timeout=5).json()["result"]
    else:
        res = requests.get(f"{urlRPC}/commit", timeout=5).json()["result"]
    signatures = res["signed_header"]["commit"]["signatures"]
    addresses = [
        sig["validator_address"] for sig in signatures if sig["validator_address"]
    ]
    return addresses


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


def collect_cli_validator_set(urlRPC: str, height: int = 0, binary: str = "gaiad"):
    """
    Obtain the validator set
    """
    if height > 0:
        p = command.run(
            [
                binary,
                "q",
                "comet-validator-set",
                str(height),
                "--node",
                urlRPC,
                "--output",
                "json",
            ]
        )
    else:
        p = command.run(
            [binary, "q", "comet-validator-set", "--node", urlRPC, "--output", "json"]
        )
    response = p.output.decode("utf-8")
    response_json = json.loads(response)
    api_vals = response_json["validators"]
    total = int(response_json["pagination"]["total"])
    page = 2
    while len(api_vals) < total:
        if height > 0:
            p = command.run(
                [
                    binary,
                    "q",
                    "comet-validator-set",
                    str(height),
                    "--node",
                    urlRPC,
                    "--output",
                    "json",
                    "--page",
                    str(page),
                ]
            )
        else:
            p = command.run(
                [
                    binary,
                    "q",
                    "comet-validator-set",
                    "--node",
                    urlRPC,
                    "--output",
                    "json",
                    "--page",
                    str(page),
                ]
            )
        response = p.output.decode("utf-8")
        response_json = json.loads(response)
        api_vals.extend(response_json["validators"])
        page += 1
    return api_vals


def get_validator_provider_address_permissionless(
    address: str, consumer_id: str, urlRPC: str, height: int = 0, binary: str = "gaiad"
):
    """
    Obtain the provider validator address given a consumer chain id and the cosmosvalcons there
    """
    if height > 0:
        p = command.run(
            [
                binary,
                "q",
                "provider",
                "validator-provider-key",
                consumer_id,
                address,
                "--height",
                str(height),
                "--node",
                urlRPC,
                "--output",
                "json",
            ]
        )
    else:
        p = command.run(
            [
                binary,
                "q",
                "provider",
                "validator-provider-key",
                consumer_id,
                address,
                "--node",
                urlRPC,
                "--output",
                "json",
            ]
        )
    response = p.output.decode("utf-8")
    response_json = json.loads(response)
    return response_json["provider_address"]


def get_validator_consumer_address_permissionless(
    address: str, consumer_id: str, urlRPC: str, height: int = 0, binary: str = "gaiad"
):
    """
    Obtain the consumer validator address given its provider cosmosvalcons and the consumer id
    """
    if height > 0:
        p = command.run(
            [
                binary,
                "q",
                "provider",
                "validator-consumer-key",
                consumer_id,
                address,
                "--height",
                str(height),
                "--node",
                urlRPC,
                "--output",
                "json",
            ]
        )
    else:
        p = command.run(
            [
                binary,
                "q",
                "provider",
                "validator-consumer-key",
                consumer_id,
                address,
                "--node",
                urlRPC,
                "--output",
                "json",
            ]
        )
    response = p.output.decode("utf-8")
    response_json = json.loads(response)
    return response_json["consumer_address"]


def get_consumer_chains_permissionless(urlAPI: str, height: int = 0):
    """
    Returns a list of consumer chains
    """
    endpoint = f"{urlAPI}/interchain_security/ccv/provider/consumer_chains/0"
    if height > 0:
        response = requests.get(
            endpoint, headers={"x-cosmos-block-height": f"{height}"}
        ).json()
    else:
        response = requests.get(endpoint).json()
    if "chains" in response:
        return [
            chain["consumer_id"]
            for chain in response["chains"]
            if chain["phase"] == "CONSUMER_PHASE_LAUNCHED"
        ]
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
# From signature_counter/signature_counter.py
# ---------------------------------------------------------------------------

class Signature_Counter():
    def __init__(self,
                 rpc: str = 'http://localhost:26657',
                 start_height: int = 1,
                 end_height: int = 0,
                 step_size: int = 1,
                 signature_count: str = 'signature_count.json',
                 read_previous_data: bool = True,
                 previous_run_data: str = 'signature_count.json'):
        self.rpc = rpc
        self.output = signature_count
        self.read_previous_data = read_previous_data
        self.previous_run_data = previous_run_data

        self.signatures = {
            'last_block': 0,
            'counter': 0,
            'signatures': {}
        }
        self.start_height = start_height
        self.end_height = end_height
        self.step_size = step_size

    def load_count(self):
        '''
        Read existing count in
        '''
        if os.path.isfile(self.previous_run_data):
            logging.info("Found existing signature count file.")
            with open(self.previous_run_data, 'r') as input:
                self.signatures = json.load(input)
                self.start_height = self.signatures['last_block'] + 1
        else:
            with open(self.previous_run_data, 'w') as output:
                json.dump(self.signatures, output, indent=4)

    def count_signatures(self):
        '''
        Count total signatures
        '''
        if self.read_previous_data:
            self.load_count()
        logging.info(f'Counting signatures from block {self.start_height}.')
        if self.end_height == 0:
            block = get_block(self.rpc)
            self.end_height = int(block['header']['height'])
        if self.start_height > self.end_height:
            logging.info('Start height is higher than end height.')
            return
        if self.signatures['last_block'] + self.step_size >= self.end_height:
            logging.info('Last recorded block + step size goes past the end height.')
            return
        for height in range(self.start_height, self.end_height, self.step_size):
            signers = signatures_bytes_addrs(self.rpc, block=height)
            for address in signers:
                if address in self.signatures['signatures'].keys():
                    self.signatures['signatures'][address] += 1
                else:
                    self.signatures['signatures'][address] = 1
            self.signatures['last_block'] = height
            self.signatures['counter'] += 1
            if (self.signatures['counter'] % 1000) == 0:
                block = get_block(self.rpc, height)
                timestamp = block['header']['time']
                logging.info(f'Reached height {height} ({timestamp}).')
                self.save_count()
        self.save_count()

    def save_count(self):
        '''
        Save current status
        '''
        with open(self.output, 'w', encoding='utf-8') as output:
            json.dump(self.signatures, output, indent=4)


# ---------------------------------------------------------------------------
# From address_book/address_book_builder.py
# ---------------------------------------------------------------------------

class AddressBookBuilder():
    '''
    Assemble an address book using the API validators endpoint as a starting point.
    1. API: cosmosvaloper, pubkey, moniker
    2. RPC: bytes address
    3. keys parsing: cosmosvalcons, self-delegation addresses
    4. consumer chain keys
    '''
    def __init__(self, rpc, api, block: int = 0,
                 inactive=False,
                 consumers=[],
                 record='addressbook.json',
                 output='addressbook.csv',
                 sdk='v47', consumer_data=True):
        self.rpc = rpc
        self.api = api
        self.collect_inactive = inactive
        self.consumers = consumers
        self.record_file = record
        self.output_file = output
        self.sdk = sdk
        self.block = block
        self.pubkey_address_dict = {}
        self.pubkey_valcons_dict = {}
        self.consumer_chains = []
        self.recorded_consumers = []
        self.address_book = {}
        self.recorded_data = {
            'block': 0, 'validators': []
        }
        self.address_book_list = []
        self.consumer_data = consumer_data
        self.load_record()

    def load_record(self):
        if os.path.exists(self.record_file):
            with open(self.record_file, 'r', encoding='utf-8') as input_file:
                self.recorded_data = json.load(input_file)
        else:
            logging.info('Record file does not exist, will create one.')
            with open(self.record_file, 'w', encoding='utf-8') as output_file:
                json.dump(self.recorded_data, output_file, indent=4)

    def load_pubkey_dicts(self, height):
        rpc_validators = collect_rpc_validators(self.rpc, height)
        self.pubkey_address_dict = {
            val['pub_key']['value']: val['address']
            for val in rpc_validators
        }
        validator_set = collect_cli_validator_set(self.rpc, height=height)
        self.pubkey_valcons_dict = {
            val['pub_key']['key']: val['address']
            for val in validator_set
        }

    def populate_consumer_chain(self, chain: str):
        for _, val_data in self.address_book.items():
            cosmosvalcons = val_data['cosmosvalcons']
            consumer_valcons = ''
            val_data[chain] = {
                'cosmosvalcons': cosmosvalcons,
                'address': val_data['address']
            }
            if cosmosvalcons:
                consumer_valcons = get_validator_consumer_address_permissionless(
                    cosmosvalcons,
                    chain,
                    self.rpc,
                    self.block
                )
                if consumer_valcons:
                    val_data[chain]['cosmosvalcons'] = consumer_valcons
                    val_data[chain]['address'] = consensus_address_to_bytes(consumer_valcons)
                else:
                    val_data[chain]['cosmosvalcons'] = cosmosvalcons
                    val_data[chain]['address'] = consensus_address_to_bytes(cosmosvalcons)

    def record_data(self):
        if self.recorded_data['block'] < self.block:
            self.recorded_data['block'] = self.block
            for val in self.address_book_list:
                valoper = val['cosmosvaloper']
                found = False
                for recorded_val in self.recorded_data['validators']:
                    recorded_valoper = recorded_val['cosmosvaloper']
                    if valoper == recorded_valoper:
                        recorded_val['moniker'] = val['moniker']
                        recorded_val['contact'] = val['contact']
                        recorded_val['cosmos'] = val['cosmos']
                        if val['address']:
                            recorded_val['address'] = val['address']
                        if val['cosmosvalcons']:
                            recorded_val['cosmosvalcons'] = val['cosmosvalcons']
                        if val['pubkey']:
                            recorded_val['pubkey'] = val['pubkey']
                        recorded_val['status'] = val['status']
                        for chain in self.recorded_consumers:
                            if chain in recorded_val.keys():
                                if val[chain]['cosmosvalcons'] and val[chain]['address']:
                                    recorded_val[chain] = {
                                        'cosmosvalcons': val[chain]['cosmosvalcons'],
                                        'address': val[chain]['address']
                                    }
                            else:
                                recorded_val[chain] = {
                                    'cosmosvalcons': val[chain]['cosmosvalcons'],
                                    'address': val[chain]['address']
                                }
                        found = True
                        break
                if not found:
                    logging.info(f'Adding validator {val["moniker"]} to record.')
                    self.recorded_data['validators'].append(val)
            with open(self.record_file, 'w', encoding='utf-8') as output:
                json.dump(self.recorded_data, output, indent=4)

    def build(self):
        if not self.block:
            logging.info("Using current block height")
            self.block = int(get_block(self.rpc)['header']['height'])
        self.load_pubkey_dicts(self.block)

        # 1. Get pubkey, cosmosvaloper, and moniker
        logging.info(f'Getting API validator data for block {self.block}')
        api_validators = collect_api_validators(self.api, self.block)

        self.address_book = {
            val['consensus_pubkey']['key']: {
                'moniker': val['description']['moniker'],
                'contact': val['description']['security_contact'],
                'cosmosvaloper': val['operator_address'],
                'cosmos': cosmosvaloper_to_cosmos(val['operator_address']),
                'address': '',
                'cosmosvalcons': '',
                'status': val['status']
            } for val in api_validators
        }

        # Filter out inactive validators
        if not self.collect_inactive:
            self.address_book = {
                key: val for key, val in self.address_book.items() if val['status'] == 'BOND_STATUS_BONDED'
            }

        # 2. Populate address and cosmosvalcons
        logging.info('Populating addresses and valcons')
        for pubkey, address in self.pubkey_address_dict.items():
            self.address_book[pubkey]['address'] = self.pubkey_address_dict[pubkey]
        for pubkey, address in self.pubkey_address_dict.items():
            if pubkey in self.pubkey_valcons_dict:
                self.address_book[pubkey]['cosmosvalcons'] = self.pubkey_valcons_dict[pubkey]

        # 2.5 RPC validator-set endpoints only return the current live
        # signing set, so validators that are jailed/unbonding/unbonded
        # (or simply new) never show up in pubkey_address_dict, even
        # though their address is a deterministic function of their
        # pubkey. Derive it directly for anything still unresolved so
        # such validators aren't silently dropped downstream.
        for pubkey, data in self.address_book.items():
            if not data['address']:
                logging.info(f'{data["moniker"]} not in live validator set, deriving address from pubkey.')
                data['address'] = consensus_pubkey_to_bytes_address(pubkey)
            if not data['cosmosvalcons']:
                data['cosmosvalcons'] = bytes_to_consensus_address(data['address'])

        # 3. Populate consumer chain keys
        self.recorded_consumers = []
        if self.consumer_data:
            logging.info('Populating consumer chain addresses')
            self.consumer_chains = get_consumer_chains_permissionless(self.api, self.block)
            for chain in self.consumer_chains:
                if self.consumers:
                    if chain in self.consumers:
                        logging.info(f'Populating data for allowlist consumer chain {chain}')
                        self.recorded_consumers.append(chain)
                        self.populate_consumer_chain(chain)
                else:
                    self.populate_consumer_chain(chain)

        for val, data in self.address_book.items():
            entry = {
                'cosmosvaloper': data['cosmosvaloper'],
                'cosmos': data['cosmos'],
                'moniker': data['moniker'],
                'contact': data['contact'],
                'pubkey': val,
                'address': data['address'],
                'cosmosvalcons': data['cosmosvalcons'],
                'status': data['status']
            }
            for chain in self.recorded_consumers:
                entry[chain] = {
                    'cosmosvalcons': data[chain]['cosmosvalcons'],
                    'address': data[chain]['address']
                }
            self.address_book_list.append(entry)
        self.record_data()

    def save_csv(self):
        '''
        Saves the address book dict to a csv file
        '''
        val_list = []

        for val in self.recorded_data['validators']:
            csv_entry = {
                'cosmosvaloper': val['cosmosvaloper'],
                'cosmos': val['cosmos'],
                'moniker': val['moniker'],
                'contact': val['contact'],
                'pubkey': val['pubkey'],
                'address': val['address'],
                'cosmosvalcons': val['cosmosvalcons'],
            }
            for chain in self.recorded_consumers:
                csv_entry[f'{chain}/cosmosvalcons'] = val[chain]['cosmosvalcons']
                csv_entry[f'{chain}/address'] = val[chain]['address']
            val_list.append(csv_entry)

        with open(self.output_file, 'w', encoding='utf-8') as output:
            fieldnames = [
                'cosmosvaloper',
                'cosmos',
                'moniker',
                'contact',
                'pubkey',
                'address',
                'cosmosvalcons'
            ]
            for chain in self.recorded_consumers:
                fieldnames.append(f'{chain}/cosmosvalcons')
                fieldnames.append(f'{chain}/address')
            output.writelines([f'Block {self.block}\n'])
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(val_list)


# ---------------------------------------------------------------------------
# Main script
# ---------------------------------------------------------------------------

def year_month_type(value):
    if not re.fullmatch(r'\d{4}-(0[1-9]|1[0-2])', value):
        raise argparse.ArgumentTypeError(f"'{value}' is not in YYYY-MM format")
    return value


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Record accounts and signed blocks in the current month.'
    )
    parser.add_argument('-r', '--rpc', type=str, help='RPC node address for provider chain, including port', default='https://rpc.provider-sentry-02.ics-testnet.polypore.xyz:443')
    parser.add_argument('-a', '--api', type=str, help='API node address, including port', default='https://rest.provider-sentry-02.ics-testnet.polypore.xyz:443')
    parser.add_argument('-s', '--step', type=int, help='Check step size', default=10)
    parser.add_argument('-m', '--year-month', type=year_month_type, help='Month to record, in YYYY-MM format', default=datetime.now().strftime('%Y-%m'))
    args = parser.parse_args()

    RPC_NODE = args.rpc
    API_NODE = args.api
    STEP_SIZE = args.step

    year_month = args.year_month
    start_time = year_month + '-01T00:00:00.000Z'
    end_time = year_month + '-31T23:59:00.000Z'

    chain_id = get_chain_id(RPC_NODE)

    signatures = {}
    print(f'> Recording signatures for {chain_id}')
    print("> Estimating block heights")
    start_height = time_to_block(rpc=RPC_NODE, time=start_time, precision=10, dampener=0.2)[0]
    end_height = time_to_block(rpc=RPC_NODE, time=end_time, precision=10, dampener=0.2)[0]
    print(f'> Checking every {STEP_SIZE} block(s) between heights {start_height} and {end_height}')
    print("> Counting signatures")
    counter = Signature_Counter(
        rpc=RPC_NODE,
        start_height=start_height,
        end_height=end_height,
        step_size=STEP_SIZE,
        signature_count=f'{chain_id}-count-{year_month}.json',
        read_previous_data=True,
        previous_run_data=f'{chain_id}-count-{year_month}.json'
    )
    counter.count_signatures()
    block_count = counter.signatures['counter']

    signatures_count = {
        bytes_to_consensus_address(signer): counter.signatures['signatures'][signer]
        for signer in list(counter.signatures['signatures'].keys())
    }

    print("> Building address book.")
    addressbook = AddressBookBuilder(RPC_NODE, API_NODE, consumer_data=False, inactive=True)
    addressbook.build()
    validators = [
        {
            'cosmos': data['cosmos'],
            'cosmosvaloper': data['cosmosvaloper'],
            'moniker': data['moniker'],
            'provider_address': data['address'],
            'provider_consensus': bytes_to_consensus_address(data['address'])
        } for pubkey, data in addressbook.address_book.items() if data['address']
    ]

    provider_consensus_dict = {
        val['provider_consensus']: {
            'cosmos': val['cosmos'],
            'cosmosvaloper': val['cosmosvaloper'],
            'moniker': val['moniker'],
            'provider_key': val['provider_consensus']
        }
        for val in validators
    }

    print("> Record signer info.")
    for provider_consensus in list(provider_consensus_dict.keys()):
        provider_consensus_dict[provider_consensus]['signatures'] = 0
        provider_consensus_dict[provider_consensus]['uptime'] = 0.0
        if provider_consensus in signatures_count:
            provider_consensus_dict[provider_consensus]['signatures'] = signatures_count[provider_consensus]
            provider_consensus_dict[provider_consensus]['uptime'] = signatures_count[provider_consensus] / block_count

    entries = []
    for val, val_data in provider_consensus_dict.items():
        entry = {
            k: v for k, v in val_data.items()
        }
        entries.append(entry)

    output_filename = f'{year_month}-{chain_id}-uptime.csv'
    print(f'> Saving to {output_filename}.')
    with open(output_filename, 'w', encoding='utf-8') as output:
        headers = list(entries[0].keys())
        writer = csv.DictWriter(output, fieldnames=headers)
        writer.writeheader()
        writer.writerows(entries)
