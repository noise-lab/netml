"""A demo for parsing pcap and labelling the extracted flows.

"""
# Authors: kun.bj@outlook.com
#
# License: xxx
import os
from pparser.parser import PCAP
from utils.tool import dump_data

RANDOM_STATE = 42


def main():
    pcap_file = 'data/demo.pcap'
    pp = PCAP(pcap_file, flow_ptks_thres=2, verbose=10, random_state=RANDOM_STATE)

    # extract flows from pcap
    pp.pcap2flows(q_interval=0.9)

    # label each flow with a label
    label_file = 'data/demo.csv'
    pp.label_flows(label_file=label_file)

    # extract features from each flow given feat_type
    feat_type = 'IAT'
    pp.flow2features(feat_type, fft=False, header=False)

    # dump data to disk
    X, y = pp.features, pp.labels
    out_dir = os.path.join('out', os.path.dirname(pcap_file))
    dump_data((X, y), out_file=f'{out_dir}/demo_{feat_type}.dat')

    print(pp.features.shape, pp.pcap2flows.tot_time, pp.flow2features.tot_time)


if __name__ == '__main__':
    main()
