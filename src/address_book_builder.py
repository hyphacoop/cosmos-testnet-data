#!/usr/bin/env python3
'''
Builds an address book of every validator in a given chain (bonded,
unbonding, and unbonded) at a specified block height, including:
- valoper address
- account address
- moniker
- security contact
- consensus pubkey
- consensus address (hex bytes and valcons formats)
- bond status
- jailed or not

All addresses are derived from the staking API's operator address and
consensus pubkey, so validators outside the live signing set are covered too.

Arguments:
- rpc endpoint
- api endpoint
- block height (optional, default: latest)
- output filename (optional)

Standalone: the only third-party dependency is `requests` (Python 3.9+).

Example:
python address_book_builder.py \
    -r <rpc endpoint> \
    -a <api endpoint>
'''

from datetime import datetime, timezone
import argparse
import base64
import csv
import hashlib
import logging
import urllib.parse

import requests

REQUEST_TIMEOUT = 30

STATUS_ORDER = {
    'BOND_STATUS_BONDED': 0,
    'BOND_STATUS_UNBONDING': 1,
    'BOND_STATUS_UNBONDED': 2,
}

FIELDNAMES = [
    'cosmosvaloper',
    'cosmos',
    'moniker',
    'contact',
    'pubkey',
    'address',
    'cosmosvalcons',
    'status',
    'jailed',
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


# ---- RPC/API queries ----

def get_chain_id(rpc: str) -> str:
    response = requests.get(f'{rpc}/status', timeout=REQUEST_TIMEOUT).json()
    return response['result']['node_info']['network']


def get_block(rpc: str, height: int = 0) -> dict:
    params = {'height': height} if height > 0 else {}
    response = requests.get(f'{rpc}/block', params=params, timeout=REQUEST_TIMEOUT).json()
    return response['result']['block']


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


# ---- address book ----

def build_address_book(api: str, height: int) -> list:
    '''
    Returns one address book entry per validator, sorted by bond status
    (bonded first) and then moniker.
    '''
    address_book = []
    for val in collect_api_validators(api, height):
        cosmosvaloper = val['operator_address']
        pubkey = val['consensus_pubkey']['key']
        address = consensus_pubkey_to_bytes_address(pubkey)
        address_book.append({
            'cosmosvaloper': cosmosvaloper,
            'cosmos': cosmosvaloper_to_cosmos(cosmosvaloper),
            'moniker': val['description']['moniker'],
            'contact': val['description']['security_contact'],
            'pubkey': pubkey,
            'address': address,
            'cosmosvalcons': bytes_to_consensus_address(address, cosmosvaloper),
            'status': val['status'],
            'jailed': val['jailed'],
        })
    address_book.sort(key=lambda entry: (STATUS_ORDER.get(entry['status'], len(STATUS_ORDER)),
                                         entry['moniker'].lower()))
    return address_book


def save_csv(address_book: list, output_file: str):
    with open(output_file, 'w', encoding='utf-8', newline='') as output:
        writer = csv.DictWriter(output, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(address_book)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Build a CSV address book of every validator in a chain.'
    )
    parser.add_argument('-r', '--rpc', type=str, required=True, help='RPC node address, including port')
    parser.add_argument('-a', '--api', type=str, required=True, help='API node address, including port')
    parser.add_argument('--height', type=int, default=0, help='Block height to query (default: latest)')
    parser.add_argument('-o', '--output', type=str, help='Filename to save the address book to (default: address_book.<chain-id>.<YYYY-MM-DD>.csv)')
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )

    chain_id = get_chain_id(args.rpc)
    height = args.height or int(get_block(args.rpc)['header']['height'])
    output_file = args.output or f'address_book.{chain_id}.{datetime.now(timezone.utc):%Y-%m-%d}.csv'

    logging.info(f'Building address book for {chain_id} at block {height}')
    address_book = build_address_book(args.api, height)
    bonded = sum(1 for entry in address_book if entry['status'] == 'BOND_STATUS_BONDED')
    logging.info(f'Collected {len(address_book)} validators ({bonded} bonded)')

    save_csv(address_book, output_file)
    logging.info(f'Saved address book to {output_file}')
