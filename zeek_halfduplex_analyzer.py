#!/usr/bin/env python3

import os
import sys
import pandas as pd
from tabulate import tabulate

type_mapping = {
    'time': 'datetime64',
    'string': 'object',
    'bool': 'bool',
    'addr': 'object',
    'port': 'Int64',
    'enum': 'object',
    'interval': 'float64',
    'count': 'Int64',
    'set[string]': 'object'
}


def zero_division_ok(numerator, denominator):
    return numerator / denominator if denominator else 0


def main():
    if len(sys.argv) < 2:
        print('No file specified to analyze', file=sys.stderr)
        sys.exit(-1)
    elif not os.path.exists(sys.argv[1]):
        print('File specified does not exist: {}'.format(sys.argv[1]), file=sys.stderr)
        sys.exit(-1)
    input_file = sys.argv[1]

    with open(input_file, 'r') as infile:
        for line in infile:
            if not line.startswith('#fields'):
                continue

            col_names = line.split()[1:]
            col_types = infile.readline().split()[1:]
            break

    # Create a dictionary of column_name:pandas_type
    converted_col_types = {}
    for col, t in zip(col_names, col_types):
        converted_col_types[col] = type_mapping[t]

    interesting_cols = ['id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'history',
                        'local_orig', 'local_resp', 'peer']
    df = pd.read_table(input_file, skiprows=8, names=col_names, sep='\s+', usecols=interesting_cols,
                       dtype=converted_col_types,
                       true_values=['T'], false_values=['F'], na_values=['-'], comment='#')

    total_lines = df.shape[0]

    # All of these are per the source code of bro doctor

    # Keep only TCP, and drop the protocol column
    df = df.loc[df['proto'] == 'tcp']
    df = df.drop(columns=['proto'])

    # Ignore connections not from our address space, then drop the unneeded columns
    df = df.loc[(df['local_orig'] == True) & (df['local_resp'] == True)]
    df = df.drop(columns=['local_orig', 'local_resp'])

    tcp_lines = df.shape[0]

    # Strip the leading carat in history
    df['history'] = df['history'].str.lstrip('^')

    # Keep only connections with multi-character histories
    df = df.loc[df['history'].str.len() > 1]

    analyzed_lines = df.shape[0]

    df = df.loc[(df['history'].str.isupper()) | (df['history'].str.islower())]

    halfduplex_lines = df.shape[0]

    print('Summary:')
    print('* {:,} total conns'.format(total_lines))
    print('* {:,} total local orig/local resp TCP conns'.format(tcp_lines))
    print('* {:,} local TCP conns with history, {:.1%} of the total (analyzed conns)'.
          format(analyzed_lines, (zero_division_ok(analyzed_lines, total_lines))))
    print('* {:,} half-duplex conns, {:.1%} of the analyzed conns and {:.1%} of the total conns'.
          format(halfduplex_lines,
               zero_division_ok(halfduplex_lines, analyzed_lines),
               zero_division_ok(halfduplex_lines, total_lines)))

    # Analyze all upper case and all lower case
    lowercase_lines = df.loc[df['history'].str.islower()].shape[0]
    uppercase_lines = df.loc[df['history'].str.isupper()].shape[0]
    print('* {} ({:.1%}) of these are lowercase, and {} ({:.1%}) are uppercase'.
          format(lowercase_lines,
                 zero_division_ok(lowercase_lines, halfduplex_lines),
                 uppercase_lines,
                 zero_division_ok(uppercase_lines, halfduplex_lines)))

    # Make sure lowercase + uppercase equals the total number of half-duplex
    assert (halfduplex_lines == (lowercase_lines + uppercase_lines))

    print('\nTop ten half-duplex history types:')
    hist_types = df['history'].value_counts().to_frame()
    hist_types['freq'] = df['history'].value_counts(normalize=True)
    for index, row in hist_types.head(n=10).iterrows():
        print('* {} - {:,} ({:.1%})'.format(index, row['history'], row['freq']))

    print('\nTop IP address pairs:')
    df['ip_pair'] = df.apply(lambda row: row['id.orig_h'] + '-' + row['id.resp_h']
    if row['id.orig_h'] < row['id.resp_h']
    else row['id.resp_h'] + '-' + row['id.orig_h'],
                             axis=1)
    pair_counts = df['ip_pair'].value_counts().to_frame()
    pair_counts['freq'] = df['ip_pair'].value_counts(normalize=True)
    for index, row in pair_counts.head(n=10).iterrows():
        print(
            '* {} and {} - {:,} ({:.1%})'.format(index.split('-')[0], index.split('-')[1], row['ip_pair'], row['freq']))

    df = df.drop(columns=['ip_pair'])

    df['nic'] = df.apply(lambda row: row['peer'].split('-')[1],
                         axis=1)
    df['process'] = df.apply(lambda row: row['peer'].split('-')[2],
                             axis=1)
    df['process'] = pd.to_numeric(df['process'])

    # End up with process across the top and nics down the side
    nics_df = df.groupby(['nic', 'process'])['history'].count().unstack()
    nics_df['Total'] = nics_df.sum(axis=1)

    # If it's wider than it is long (rows < cols), transpose it so nic is across the top
    num_nics, num_procs = nics_df.shape
    if num_nics < num_procs:
        nics_df = nics_df.T

    # Clean up from the groupby - remove column names so they don't show in table
    nics_df = nics_df.rename_axis(None)
    nics_df = nics_df.rename_axis(None, axis=1)
    nics_df = nics_df.fillna(0)

    print('\nHalf-duplex connections by NIC and process (count):')
    print(tabulate(nics_df, headers='keys', tablefmt='plain', floatfmt=',.0f'))
    print('\nEvenly spaced average by process is {:,.1f}'.format(
        zero_division_ok(halfduplex_lines, (num_nics * num_procs))))
    print('Evenly spaced average by NIC is {:,.1f}'.format(zero_division_ok(halfduplex_lines, num_nics)))

    nics_df = zero_division_ok(nics_df, halfduplex_lines)
    nics_df = nics_df.fillna(0)
    print('\nHalf-duplex connections by NIC and process (percentage):')
    print(tabulate(nics_df, headers='keys', tablefmt='plain', floatfmt='.2%'))
    print('\nEvenly spaced average by process is {:,.1%}'.format(zero_division_ok(1, (num_nics * num_procs))))
    print('Evenly spaced average by NIC is {:,.1%}'.format(zero_division_ok(1, num_nics)))

    # See a graph by nic and process
    # axis = df.groupby(['nic', 'process'])['history'].count().unstack().plot(kind='bar', stacked=True)

    # Drop the extra columns
    df = df.drop(columns=['nic', 'process'])

    # Add an identifier for srcIP-srcPort-dstIP-dstPort
    df['conn_id'] = df.apply(lambda row: row['id.orig_h'] + '/' + str(row['id.orig_p']) +
                                         '-' + row['id.resp_h'] + '/' + str(row['id.resp_p']),
                             axis=1)

    # Add a reverse identifier for dstIP-dstPort-srcIP-srcPort
    df['reverse_id'] = df.apply(lambda row: row['id.resp_h'] + '/' + str(row['id.resp_p']) +
                                            '-' + row['id.orig_h'] + '/' + str(row['id.orig_p']),
                                axis=1)

    # Add an identifier for the flow that's unique per connection (same on both sides), so we can later drop one side of pairs
    df['flow_id'] = df.apply(lambda row: row['conn_id'] if row['conn_id'] < row['reverse_id'] else row['reverse_id'],
                             axis=1)

    # Inner self-join - see https://pandas.pydata.org/docs/getting_started/comparison/comparison_with_sql.html#inner-join
    merged_df = pd.merge(df, df, left_on='conn_id', right_on='reverse_id')

    # Now only keep the ones where conn_id equals flow_id
    merged_df = merged_df[merged_df['conn_id_x'] == merged_df['flow_id_x']]

    # Multiply by two in calculations because we need to count both sides of the connection
    print('\nHalf-duplex connections with presumably both sides seen separately:')
    print('* {} ({:.1%}) connections'.format(merged_df.shape[0] * 2, zero_division_ok(merged_df.shape[0] * 2,
                                                                                      halfduplex_lines)))

    print('* Top ten history types for conns with both sides seen:')
    hist_types = merged_df['history_x'].value_counts().to_frame()
    hist_types['freq'] = merged_df['history_x'].value_counts(normalize=True)
    for index, row in hist_types.head(n=10).iterrows():
        print('  * {} - {:,} ({:.1%})'.format(index, row['history_x'], row['freq']))


if __name__ == '__main__':
    main()
