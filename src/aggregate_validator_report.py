'''
Builds a month-to-date "master" validator report from the daily CSVs
produced by validator_report.py, without re-scanning the chain.

Merging logic per validator (keyed by cosmosvaloper, the one identifier
that's stable even across consensus-key rotation):
- identity fields (cosmos, moniker, pubkey, address, cosmosvalcons) and
  current status (bonded, jailed) are taken from the most recent daily
  file the validator appears in
- left_active_set / joined_active_set / jailed_during_period are OR'd
  across all daily files
- left_heights / joined_heights are the concatenation of every daily
  file's heights, in day order
- jailed_time / jailed_block / jailed_reason are taken from the first
  daily file that reports a jailing (the normal case is at most one
  jailing event per validator per month)

This produces the same result as running validator_report.py directly
with a YYYY-MM period, provided a daily CSV exists for every day of the
month scanned so far, and this is run on (or after) the day the last of
those daily CSVs was collected -- otherwise "current status" reflects
whatever day the aggregation was last run, not necessarily today.

Example:
python -m validator_report.aggregate_validator_report \
    -p 2026-09 \
    -d data_collected
'''

from datetime import date
import argparse
import calendar
import csv
import glob
import logging
import os.path
import re

logging.basicConfig(
    filename=None,
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)

FIELDNAMES = [
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

HEADER_BLOCKS_RE = re.compile(r'blocks (\d+)-(\d+)')


def find_daily_reports(directory: str, period: str):
    '''
    Returns the sorted list of daily report paths for the given YYYY-MM
    period found in `directory` (sorting alphabetically also sorts them
    chronologically, since the filenames are ISO dates).
    '''
    pattern = os.path.join(directory, f'validator_report.{period}-??.csv')
    return sorted(glob.glob(pattern))


def read_daily_report(path: str):
    '''
    Returns (start_block, end_block, rows) for one daily CSV, where
    rows is a list of dicts as written by validator_report.py's
    save_csv().
    '''
    with open(path, 'r', encoding='utf-8') as input_file:
        header_line = input_file.readline()
        reader = csv.DictReader(input_file)
        rows = list(reader)
    match = HEADER_BLOCKS_RE.search(header_line)
    start_block = int(match.group(1)) if match else None
    end_block = int(match.group(2)) if match else None
    return start_block, end_block, rows


def split_heights(value: str):
    return [h for h in value.split('|') if h]


def merge_daily_reports(paths):
    '''
    Folds a chronological list of daily report paths into a single
    dict keyed by cosmosvaloper, plus the overall (first_start_block,
    last_end_block) span.
    '''
    merged = {}
    first_start_block = None
    last_end_block = None

    for path in paths:
        start_block, end_block, rows = read_daily_report(path)
        if first_start_block is None:
            first_start_block = start_block
        last_end_block = end_block

        for row in rows:
            key = row['cosmosvaloper']
            left_heights = split_heights(row['left_heights'])
            joined_heights = split_heights(row['joined_heights'])
            jailed_during_period = row['jailed_during_period'] == 'True'

            if key not in merged:
                merged[key] = {
                    'cosmosvaloper': row['cosmosvaloper'],
                    'cosmos': row['cosmos'],
                    'moniker': row['moniker'],
                    'pubkey': row['pubkey'],
                    'address': row['address'],
                    'cosmosvalcons': row['cosmosvalcons'],
                    'bonded': row['bonded'],
                    'jailed': row['jailed'],
                    'left_heights': [],
                    'joined_heights': [],
                    'jailed_during_period': False,
                    'jailed_time': '',
                    'jailed_block': '',
                    'jailed_reason': '',
                }

            entry = merged[key]
            # Identity/current-status fields: most recent daily file wins.
            entry['cosmos'] = row['cosmos']
            entry['moniker'] = row['moniker']
            entry['pubkey'] = row['pubkey']
            entry['address'] = row['address']
            entry['cosmosvalcons'] = row['cosmosvalcons']
            entry['bonded'] = row['bonded']
            entry['jailed'] = row['jailed']

            entry['left_heights'].extend(left_heights)
            entry['joined_heights'].extend(joined_heights)

            if jailed_during_period:
                entry['jailed_during_period'] = True
                if not entry['jailed_time'] and not entry['jailed_block'] and not entry['jailed_reason']:
                    entry['jailed_time'] = row['jailed_time']
                    entry['jailed_block'] = row['jailed_block']
                    entry['jailed_reason'] = row['jailed_reason']

    return merged, first_start_block, last_end_block


def build_rows(merged):
    rows = []
    for entry in merged.values():
        rows.append({
            'cosmosvaloper': entry['cosmosvaloper'],
            'cosmos': entry['cosmos'],
            'moniker': entry['moniker'],
            'pubkey': entry['pubkey'],
            'address': entry['address'],
            'cosmosvalcons': entry['cosmosvalcons'],
            'bonded': entry['bonded'],
            'jailed': entry['jailed'],
            'left_active_set': bool(entry['left_heights']),
            'left_heights': '|'.join(entry['left_heights']),
            'joined_active_set': bool(entry['joined_heights']),
            'joined_heights': '|'.join(entry['joined_heights']),
            'jailed_during_period': entry['jailed_during_period'],
            'jailed_time': entry['jailed_time'],
            'jailed_block': entry['jailed_block'],
            'jailed_reason': entry['jailed_reason'],
        })
    rows.sort(key=lambda row: row['moniker'].lower())
    return rows


def save_csv(output_file, period, first_start_block, last_end_block, num_reports, rows):
    with open(output_file, 'w', encoding='utf-8') as output:
        block_range = f'{first_start_block}-{last_end_block}' if first_start_block is not None else 'unknown'
        output.writelines([
            f'Period {period}, blocks {block_range} '
            f'(aggregated from {num_reports} daily reports)\n'
        ])
        writer = csv.DictWriter(output, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)
    logging.info(f'Saved {len(rows)} validators to {output_file}')


def period_type(value):
    if not re.fullmatch(r'\d{4}-(0[1-9]|1[0-2])', value):
        raise argparse.ArgumentTypeError(f"'{value}' is not in YYYY-MM format")
    return value


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Build a month-to-date master validator report by merging the '
                     'daily CSVs validator_report.py already produced for that month.'
    )
    parser.add_argument('-p', '--period', type=period_type, required=True, help='Month to aggregate, in YYYY-MM format')
    parser.add_argument('-d', '--data-dir', type=str, default='data_collected', help='Root directory holding <year>/<month>/ daily reports (default: data_collected)')
    parser.add_argument('-o', '--output', type=str, help='Filename to save the master report to (default: <data-dir>/<year>/<month>/validator_report.<period>.csv)')

    args = parser.parse_args()

    year, month = args.period.split('-')
    directory = os.path.join(args.data_dir, year, month)
    output_file = args.output or os.path.join(directory, f'validator_report.{args.period}.csv')

    daily_reports = find_daily_reports(directory, args.period)
    if not daily_reports:
        raise SystemExit(f'No daily reports found for {args.period} in {directory}')
    logging.info(f'Aggregating {len(daily_reports)} daily reports from {directory}')

    merged, first_start_block, last_end_block = merge_daily_reports(daily_reports)
    rows = build_rows(merged)
    save_csv(output_file, args.period, first_start_block, last_end_block, len(daily_reports), rows)
