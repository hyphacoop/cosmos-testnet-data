#!/usr/bin/env python3
'''
Saves a CSV listing every validator in the chain (bonded, unbonding, and
unbonded) with its self-delegation wallet and whether it signed at least
one block within a given block range, including:
- account address (self-delegation wallet)
- valoper address
- moniker
- consensus address (hex bytes)
- signed (True if at least one block in the range was signed)
- number of blocks signed in the range

Only BLOCK_ID_FLAG_COMMIT signatures are counted; absent and nil votes
are not.

Arguments:
- rpc endpoint (default: testnet provider sentry-02)
- api endpoint (default: testnet provider sentry-02)
- start height
- end height (not included)
- output filename (optional)

Standalone: the only third-party dependency is `requests` (Python 3.9+).

Example:
python block_range_signers.py -s 18257202 -e 18257207
'''

from concurrent.futures import ThreadPoolExecutor
import argparse
import base64
import csv
import hashlib
import logging
import time
import urllib.parse

import requests

REQUEST_TIMEOUT = 30
REQUEST_RETRIES = 3
BLOCK_ID_FLAG_COMMIT = 2

DEFAULT_RPC = 'https://rpc.provider-sentry-02.hub-testnet.polypore.xyz'
DEFAULT_API = 'https://rest.provider-sentry-02.hub-testnet.polypore.xyz'

FIELDNAMES = [
    'cosmos',
    'cosmosvaloper',
    'moniker',
    'address',
    'signed',
    'signed_blocks',
]


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
    SHA-256 hash of the raw pubkey.
    '''
    return hashlib.sha256(base64.b64decode(pubkey)).digest()[:20].hex().upper()


# ---- RPC/API queries ----

def get_chain_id(rpc: str) -> str:
    response = requests.get(f'{rpc}/status', timeout=REQUEST_TIMEOUT).json()
    return response['result']['node_info']['network']


def get_block(rpc: str, height: int = 0) -> dict:
    params = {'height': height} if height > 0 else {}
    response = requests.get(f'{rpc}/block', params=params, timeout=REQUEST_TIMEOUT).json()
    return response['result']['block']


def get_earliest_height(rpc: str) -> int:
    response = requests.get(f'{rpc}/status', timeout=REQUEST_TIMEOUT).json()
    return int(response['result']['sync_info']['earliest_block_height'])


def collect_api_validators(api: str, height: int = 0) -> list:
    '''
    Collects every validator from the staking module at the specified
    height (latest if 0), regardless of bond status.
    '''
    headers = {'x-cosmos-block-height': str(height)} if height > 0 else {}
    url = f'{api}/cosmos/staking/v1beta1/validators?pagination.limit=1000'
    response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT).json()
    validators = response['validators']
    next_key = response['pagination']['next_key']
    while next_key:
        response = requests.get(
            f'{url}&pagination.key={urllib.parse.quote(next_key)}',
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        ).json()
        validators.extend(response['validators'])
        next_key = response['pagination']['next_key']
    return validators


def get_commit_signers(rpc: str, height: int) -> set:
    '''
    Returns the hex addresses of the validators that committed a
    signature for the given block, retrying on transient errors.
    '''
    for attempt in range(1, REQUEST_RETRIES + 1):
        try:
            response = requests.get(f'{rpc}/commit', params={'height': height},
                                    timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            signatures = response.json()['result']['signed_header']['commit']['signatures']
            return {
                sig['validator_address'] for sig in signatures
                if int(sig['block_id_flag']) == BLOCK_ID_FLAG_COMMIT
            }
        except (requests.RequestException, KeyError, ValueError) as error:
            if attempt == REQUEST_RETRIES:
                raise RuntimeError(f'Could not get commit for block {height}: {error}') from error
            logging.warning(f'Block {height}: {error} (attempt {attempt}/{REQUEST_RETRIES})')
            time.sleep(2 * attempt)


# ---- signature count ----

def count_signatures(rpc: str, start: int, end: int, workers: int) -> dict:
    '''
    Returns {hex address: number of blocks signed} for the block range
    [start, end) (end not included).
    '''
    counts = {}
    total = end - start
    with ThreadPoolExecutor(max_workers=workers) as executor:
        for done, signers in enumerate(
                executor.map(lambda height: get_commit_signers(rpc, height), range(start, end)),
                start=1):
            for address in signers:
                counts[address] = counts.get(address, 0) + 1
            if done % 1000 == 0 or done == total:
                logging.info(f'Processed {done}/{total} blocks')
    return counts


def build_rows(api: str, counts: dict) -> list:
    '''
    Returns one row per validator, signers first and then by moniker.
    '''
    rows = []
    for val in collect_api_validators(api):
        cosmosvaloper = val['operator_address']
        address = consensus_pubkey_to_bytes_address(val['consensus_pubkey']['key'])
        signed_blocks = counts.get(address, 0)
        rows.append({
            'cosmos': cosmosvaloper_to_cosmos(cosmosvaloper),
            'cosmosvaloper': cosmosvaloper,
            'moniker': val['description']['moniker'],
            'address': address,
            'signed': signed_blocks > 0,
            'signed_blocks': signed_blocks,
        })
    known = {row['address'] for row in rows}
    for address in sorted(set(counts) - known):
        logging.warning(f'Signer {address} does not match any validator in the staking module')
    rows.sort(key=lambda row: (not row['signed'], row['moniker'].lower()))
    return rows


def save_csv(rows: list, output_file: str):
    with open(output_file, 'w', encoding='utf-8', newline='') as output:
        writer = csv.DictWriter(output, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Record which validators signed at least one block within a block range.'
    )
    parser.add_argument('-r', '--rpc', type=str, default=DEFAULT_RPC, help='RPC node address, including port')
    parser.add_argument('-a', '--api', type=str, default=DEFAULT_API, help='API node address, including port')
    parser.add_argument('-s', '--start', type=int, required=True, help='Start height')
    parser.add_argument('-e', '--end', type=int, required=True, help='End height (not included)')
    parser.add_argument('-o', '--output', type=str, help='Filename to save the record to (default: block_range_signers.<chain-id>.<start>-<end>.csv)')
    parser.add_argument('-w', '--workers', type=int, default=8, help='Number of concurrent RPC requests (default: 8)')
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )

    latest = int(get_block(args.rpc)['header']['height'])
    earliest = get_earliest_height(args.rpc)
    if args.start >= args.end:
        parser.error(f'Start height {args.start} must be lower than end height {args.end}')
    if args.end - 1 > latest:
        parser.error(f'Last height to check ({args.end - 1}) is greater than the latest height {latest}')
    if args.start < earliest:
        parser.error(f'Start height {args.start} is below the earliest height available on the node ({earliest})')

    chain_id = get_chain_id(args.rpc)
    output_file = args.output or f'block_range_signers.{chain_id}.{args.start}-{args.end}.csv'

    logging.info(f'Counting signatures for {chain_id} from block {args.start} to {args.end - 1}')
    counts = count_signatures(args.rpc, args.start, args.end, args.workers)

    rows = build_rows(args.api, counts)
    signed = sum(1 for row in rows if row['signed'])
    logging.info(f'{signed} of {len(rows)} validators signed at least one block')

    save_csv(rows, output_file)
    logging.info(f'Saved record to {output_file}')
