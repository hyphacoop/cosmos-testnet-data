#!/usr/bin/env python3
'''
Saves a CSV listing every address that voted on a governance proposal,
including:
- account address (voter)
- valoper address (blank if the voter is not a validator's self-delegation wallet)
- moniker (blank if the voter is not a validator's self-delegation wallet)
- vote option (e.g. yes, no, abstain, no_with_veto; weighted votes are
  written as option:weight pairs joined by ';')
- height of the block the vote was included in
- hash of the transaction

Votes are found by searching the chain's transactions, since the gov
module deletes votes once the voting period ends. Only successful
transactions are counted. If an address voted more than once, only its
latest vote is kept.

Arguments:
- proposal id
- rpc endpoint (default: testnet provider sentry-02)
- api endpoint (default: testnet provider sentry-02)
- output filename (optional)

Standalone: the only third-party dependency is `requests` (Python 3.9+).

Example:
python voters.py -p 319
'''

import argparse
import base64
import binascii
import csv
import json
import logging
import time
import urllib.parse

import requests

REQUEST_TIMEOUT = 30
REQUEST_RETRIES = 3

DEFAULT_RPC = 'https://rpc.provider-sentry-02.hub-testnet.polypore.xyz'
DEFAULT_API = 'https://rest.provider-sentry-02.hub-testnet.polypore.xyz'

VOTE_OPTIONS = {
    1: 'yes',
    2: 'abstain',
    3: 'no',
    4: 'no_with_veto',
}

FIELDNAMES = [
    'cosmos',
    'cosmosvaloper',
    'moniker',
    'option',
    'height',
    'txhash',
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


# ---- RPC/API queries ----

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


def get_chain_id(rpc: str) -> str:
    response = requests.get(f'{rpc}/status', timeout=REQUEST_TIMEOUT).json()
    return response['result']['node_info']['network']


def rpc_call(rpc: str, method: str, params: dict) -> dict:
    '''
    Issues a JSON-RPC request and returns the full response, retrying on
    transient errors. An 'error' key in the response is returned, not raised.
    '''
    for attempt in range(1, REQUEST_RETRIES + 1):
        try:
            response = requests.post(
                rpc,
                json={'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params},
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            return response.json()
        except (requests.RequestException, ValueError) as error:
            if attempt == REQUEST_RETRIES:
                raise RuntimeError(f'{method} failed: {error}') from error
            logging.warning(f'{method}: {error} (attempt {attempt}/{REQUEST_RETRIES})')
            time.sleep(2 * attempt)


def search_vote_txs(rpc: str, proposal_id: int, per_page: int = 100) -> list:
    '''
    Returns every tx containing a vote on the proposal.
    '''
    query = f"proposal_vote.proposal_id='{proposal_id}'"
    txs = []
    page = 1
    while True:
        response = rpc_call(rpc, 'tx_search', {
            'query': query,
            'page': str(page),
            'per_page': str(per_page),
            'order_by': 'asc',
        })
        if 'error' in response:
            raise RuntimeError(f"tx_search failed on page {page}: {response['error']}")
        result = response['result']
        page_txs = result.get('txs') or []
        txs.extend(page_txs)
        logging.info(f"Fetched {len(txs)}/{result.get('total_count')} transactions")
        if len(txs) >= int(result.get('total_count') or 0) or not page_txs:
            return txs
        page += 1


# ---- vote parsing ----

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


def decode_event(event: dict) -> dict:
    return {
        _maybe_b64decode(attribute.get('key', '')): _maybe_b64decode(attribute.get('value', ''))
        for attribute in event.get('attributes', [])
    }


def format_option(raw: str) -> str:
    '''
    Normalizes the proposal_vote option attribute, a JSON list of
    {option, weight} (gov v1) or a plain option name/number (gov v1beta1).
    '''
    try:
        options = json.loads(raw)
    except ValueError:
        return raw.removeprefix('VOTE_OPTION_').lower()
    if not isinstance(options, list):
        return VOTE_OPTIONS.get(options, str(options))
    names = [
        (VOTE_OPTIONS.get(int(entry['option']), str(entry['option'])), float(entry['weight']))
        for entry in options
    ]
    if len(names) == 1:
        return names[0][0]
    return ';'.join(f'{name}:{weight:g}' for name, weight in names)


def extract_votes(txs: list, proposal_id: int) -> dict:
    '''
    Returns {voter: vote row}, keeping each voter's latest vote.
    '''
    votes = {}
    for tx in txs:
        if int(tx['tx_result']['code']) != 0:
            continue
        for event in tx['tx_result']['events']:
            if event['type'] != 'proposal_vote':
                continue
            attributes = decode_event(event)
            if attributes.get('proposal_id') != str(proposal_id):
                continue
            votes[attributes['voter']] = {
                'cosmos': attributes['voter'],
                'option': format_option(attributes['option']),
                'height': int(tx['height']),
                'txhash': tx['hash'],
            }
    return votes


def build_rows(api: str, votes: dict) -> list:
    '''
    Returns one row per voter, validators first and then by address.
    '''
    validators = {
        cosmosvaloper_to_cosmos(val['operator_address']): val
        for val in collect_api_validators(api)
    }
    rows = []
    for voter, vote in votes.items():
        validator = validators.get(voter)
        rows.append({
            **vote,
            'cosmosvaloper': validator['operator_address'] if validator else '',
            'moniker': validator['description']['moniker'] if validator else '',
        })
    rows.sort(key=lambda row: (not row['moniker'], row['moniker'].lower(), row['cosmos']))
    return rows


def save_csv(rows: list, output_file: str):
    with open(output_file, 'w', encoding='utf-8', newline='') as output:
        writer = csv.DictWriter(output, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Record every address that voted on a governance proposal.'
    )
    parser.add_argument('-p', '--proposal', type=int, required=True, help='Proposal ID')
    parser.add_argument('-r', '--rpc', type=str, default=DEFAULT_RPC, help='RPC node address, including port')
    parser.add_argument('-a', '--api', type=str, default=DEFAULT_API, help='API node address, including port')
    parser.add_argument('-o', '--output', type=str, help='Filename to save the record to (default: voters.<chain-id>.<proposal>.csv)')
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )

    chain_id = get_chain_id(args.rpc)
    output_file = args.output or f'voters.{chain_id}.{args.proposal}.csv'

    logging.info(f'Collecting votes on proposal {args.proposal} for {chain_id}')
    txs = search_vote_txs(args.rpc, args.proposal)
    votes = extract_votes(txs, args.proposal)
    if not votes:
        parser.error(f'No votes found for proposal {args.proposal}')

    rows = build_rows(args.api, votes)
    validators = sum(1 for row in rows if row['moniker'])
    logging.info(f'{len(rows)} addresses voted ({validators} validators)')

    save_csv(rows, output_file)
    logging.info(f'Saved record to {output_file}')
