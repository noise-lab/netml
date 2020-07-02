"""PCAP parser
'pparser' parses pcaps to flow features by Scapy.
"""
# Authors: kun.bj@outlook.com
#
# License: xxx

import datetime
from collections import Counter, OrderedDict

import numpy as np
import pandas as pd
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from sklearn.utils import shuffle

from utils.tool import data_info, timing


def _get_fid(pkt):
    """Extract fid (five-tuple) from a packet: only focus on IPv4
    Parameters
    ----------

    Returns
    -------
        fid: five-tuple
    """

    if IP in pkt and TCP in pkt:
        flow_type = 'TCP'
        fid = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport, 6)
    elif IP in pkt and UDP in pkt:
        flow_type = 'UDP'
        fid = (pkt[IP].src, pkt[IP].dst, pkt[UDP].sport, pkt[UDP].dport, 17)
    else:
        fid = 'other'

    return fid


def _get_frame_time(pkt):
    """Get packet arrival time

    Parameters
    ----------
    pkt:
        a packet
    Returns
    -------
        pkt_time: float
    """
    return float(pkt.time)


def _get_flow_duration(pkts):
    """Get flow duration

    Parameters
    ----------
    pkts: list
        a list of packets of a flow
    Returns
    -------
        flow_duration: float
    """
    pkt_times = [_get_frame_time(pkt) for pkt in pkts]
    flow_duration = max(pkt_times) - min(pkt_times)
    return flow_duration


def _pcap2flows(pcap_file, flow_pkts_thres=2, *, tcp_timeout=600, udp_timeout=600, verbose=1):
    """Extract flows. Only keep TCP and UDP flows, others are discarded.

    Parameters
    ----------
    pcap_file: str
        a pcap needed to processed.

    flow_ptks_thres: int (default is 2)
        the minimum number of packets of each flow is to control which flow should be kept
        and which one should be discarded. The default value is 2, i.e., all the flows which have less than 2 packets
        are discarded. It must be >= 2.

    tcp_timeout: int (default is 600s)
        a timeout is to split flow

    ucp_timeout: int (default is 600s)
        a timeout is to split flow

    verbose: int (default is 1)
        a print level is to control what information should be printed according to the given value.
        The higher the value is, the more info is printed.

    Returns
    -------
        flows: list

    """

    if verbose:
        print(f'pcap_file: {pcap_file}')

    # store all extracted flows into a dictionary, whose key is flow id ('fid': five-tuple) and value is packtes
    # that belongs to the flow.
    flows = OrderedDict()
    try:
        # iteratively get each packet from the pcap
        for i, pkt in enumerate(PcapReader(pcap_file)):
            if (verbose > 3) and (i % 10000 == 0):
                print(f'ith_packets: {i}')

            if (TCP in pkt) or (UDP in pkt):

                # this function treats bidirection flows as two sessions (hereafter, we use sessions
                # and flows interchangeably).
                fid = _get_fid(pkt)

                if fid not in flows.keys():
                    flows[fid] = [pkt]
                else:
                    flows[fid].append(pkt)
            else:
                continue

    except Exception as e:
        msg = f'Parse PCAP error: {e}!'
        raise RuntimeError(msg)

    if verbose > 3:
        print(f'len(flows): {len(flows.keys())}')

    # split flows by TIMEOUT and discard flows that have less than "flow_pkts_thres" packets.
    n_pkts = 0
    new_flows = []  # store the preprocessed flows
    for i, (fid, pkts) in enumerate(flows.items()):
        n_pkts += len(pkts)
        if len(pkts) < max(2, flow_pkts_thres):
            # discard flows that have less than "max(2, flow_pkts_thres)" packets
            continue

        # Is it necessary to sort packets by arrival_times?
        pkts = sorted(pkts, key=_get_frame_time, reverse=False)

        subflows = []
        # split flows by TIMEOUT
        for j, pkt in enumerate(pkts):
            pkt_time = _get_frame_time(pkt)
            if j == 0:
                subflow_tmp = [pkt]
                split_flow = False  # if a flow is not split with interval, label it as False, otherwise, True
                continue

            if (6 in fid) or (TCP in pkt):
                # handle TCP packets, TCP is 6
                # a timeout (the idle time) is the duration between the previous pkt and the current one.
                if pkt_time - _get_frame_time(subflow_tmp[-1]) > tcp_timeout:
                    subflows.append((fid, subflow_tmp))
                    subflow_tmp = [pkt]  # create a new subflow and store the current packet as the first packet of it.
                    split_flow = True
                else:
                    subflow_tmp.append(pkt)
            elif (17 in fid) or UDP in pkt:
                # handle UDP packets, UDP is 17
                if pkt_time - _get_frame_time(subflow_tmp[-1]) > udp_timeout:
                    subflows.append((fid, subflow_tmp))
                    subflow_tmp = [pkt]
                    split_flow = True
                else:
                    subflow_tmp.append(pkt)
            else:  # it's not possible, because flows only include TCP and UDP flows
                pass

        if not split_flow:  # if the current flow is not split by TIMEOUT, then add it into subflows
            subflows.append([fid, subflow_tmp])
        else:
            # discard the last subflow_tmp
            pass

        new_flows.extend(subflows)

    if verbose > 3:
        n_lt_2 = len([len(pkts) for fid, pkts in flows.items() if len(pkts) < flow_pkts_thres])
        n_gt_2 = len([len(pkts) for fid, pkts in flows.items() if len(pkts) >= flow_pkts_thres])
        print(f'total number of flows: {len(flows.keys())}. Num of flows < {flow_pkts_thres} pkts: {n_lt_2}, '
              f'and >={flow_pkts_thres} pkts: {n_gt_2}')
        print(f'kept flows: {len(new_flows)}. Each of them has at least {flow_pkts_thres} pkts')

    return new_flows


def _flows2subflows(flows, interval=10, *, flow_pkts_thres=2, verbose=1):
    """Split flows to subflows by interval

    Parameters
    ----------
    flows: list
      all flows needed to be split

    interval: float (default is 5.0s)
       a window is to split each flow

    flow_ptks_thres: int (default is 2)
        the minimum number of packets of each flow is to control which flow should be kept
        and which one should be discarded. The default value is 2, i.e., all the flows which have less than 2 packets
        are discarded. It must be >= 2.

    verbose: int (default is 1)
        a print level is to control what information should be printed according to the given value.
        The higher the value is, the more info is printed.

    Returns
    -------
    subflows: list
        each of subflow has at least "flow_ptks_thres" packets
    """

    new_flows = []  # store all subflows
    for i, (fid, pkts) in enumerate(flows):
        if (verbose > 3) and (i % 1000) == 0:
            print(f'{i}th_flow: len(pkts): {len(pkts)}')

        # Is it necessary to sort packets by arrival_times ?
        pkts = sorted(pkts, key=_get_frame_time, reverse=False)

        subflows = []
        # split flows by TIMEOUT
        for j, pkt in enumerate(pkts):
            pkt_time = _get_frame_time(pkt)
            if j == 0:
                subflow_tmp_start_time = pkt_time
                subflow_tmp = [(subflow_tmp_start_time, pkt)]
                split_flow = False  # if a flow is not split with interval, label it as False, otherwise, True
                continue

            if (6 in fid) or (TCP in pkt):
                # handle TCP packets, TCP is 6
                # a timeout (the idle time) is the duration between the previous pkt and the current one.
                if pkt_time - subflow_tmp[-1][0] > interval:
                    subflows.append((fid, subflow_tmp))
                    subflow_tmp_start_time += int((pkt_time - subflow_tmp_start_time) // interval) * interval
                    # create a new subflow and store "subflow_tmp_start_time" as the time. Here, it will has a tiny
                    # difference of packet time between "subflow_tmp_start_time" and the current packet time.
                    subflow_tmp = [(subflow_tmp_start_time, pkt)]
                    split_flow = True
                else:
                    subflow_tmp.append((pkt_time, pkt))

            elif (17 in fid) or UDP in pkt:
                # handle UDP packets, UDP is 17
                if pkt_time - subflow_tmp[-1][0] > interval:
                    subflows.append((fid, subflow_tmp))
                    subflow_tmp_start_time += int((pkt_time - subflow_tmp_start_time) // interval) * interval
                    subflow_tmp = [(subflow_tmp_start_time, pkt)]
                    split_flow = True
                else:
                    subflow_tmp.append((pkt_time, pkt))
            else:  # it's not possible, because flows only include TCP and UDP flows
                pass

        if not split_flow:  # if the current flow is not split by TIMEOUT, then add it into subflows
            subflows.append([fid, subflow_tmp])
        else:
            # discard the last subflow_tmp
            pass

        new_flows.extend(subflows)

    # sort all flows by packet arrival time, each flow must have at least two packets
    subflows = []
    for fid, subflow_tmp in new_flows:
        if len(subflow_tmp) < max(2, flow_pkts_thres):
            continue
        subflows.append((fid, [pkt for pkt_time, pkt in subflow_tmp]))

    new_flows = subflows
    if verbose > 1:
        print(f'After splitting flows, the number of subflows: {len(new_flows)} and each of them has at least '
              f'{flow_pkts_thres} packets.')

    return new_flows


def _get_header_features(flows):
    """Extract header features which includes TCP Flags and TTL
    Parameters
    ----------

    Returns
    -------
       headers: a list
    """

    def _parse_tcp_flgs(tcp_flgs):
        # flags = {
        #     'F': 'FIN',
        #     'S': 'SYN',
        #     'R': 'RST',
        #     'P': 'PSH',
        #     'A': 'ACK',
        #     'U': 'URG',
        #     'E': 'ECE',
        #     'C': 'CWR',
        # }
        flgs = {
            'F': 0,
            'S': 0,
            'R': 0,
            'P': 0,
            'A': 0,
            'U': 0,
            'E': 0,
            'C': 0,
        }

        for flg in tcp_flgs:
            if flg in flgs.keys():
                flgs[flg] += 1

        return list(flgs.values())

    features = []
    for fid, pkts in flows:
        flgs_lst = np.zeros((8, 1))  # 8 TCP flags
        header_features = []
        for i, pkt in enumerate(pkts):
            if pkt.payload.proto == 6:  # tcp
                flgs_lst += np.asarray(_parse_tcp_flgs(pkt.payload.payload.flags)).reshape(-1, 1)  # parses tcp.flgs
            header_features.append(pkt.payload.ttl)

        features.append(list(flgs_lst.flatten()) + header_features)

    return features


def _get_IAT(flows):
    """Extract interarrival times (IAT) features  from flows.
    Parameters
    ----------

    Returns
    -------
    features: a list
        iats
    fids: a list
        each value is five-tuple
    """
    features = []
    fids = []
    for fid, pkts in flows:
        pkt_times = [_get_frame_time(pkt) for pkt in pkts]
        # some packets have the same time, please double check the pcap.
        iats = list(np.diff(pkt_times))
        features.append(iats)
        fids.append(fid)

    return features, fids


def _get_SIZE(flows):
    """Extract packet sizes features from flows
    Parameters
    ----------

    Returns
    -------
    features: a list
        sizes
    fids: a list
        each value is five-tuple
    """

    features = []
    fids = []
    for fid, pkts in flows:
        sizes = [len(pkt) for pkt in pkts]
        features.append(sizes)
        fids.append(fid)

    return features, fids


def _get_IAT_SIZE(flows):
    """Extract iats and sizes features from flows
    Parameters
    ----------

    Returns
    -------
    features: a list
        iats_sizes
    fids: a list
        each value is five-tuple
    """

    features = []
    fids = []
    for fid, pkts in flows:
        pkt_times = [_get_frame_time(pkt) for pkt in pkts]
        iats = list(np.diff(pkt_times))
        sizes = [len(pkt) for pkt in pkts]
        iats_sizes = []
        for j in range(len(iats)):
            iats_sizes.extend([iats[j], sizes[j]])
        iats_sizes.append(sizes[-1])
        features.append(iats_sizes)
        fids.append(fid)

    return features, fids


def _get_STATS(flows):
    """get basic stats features, which includes duration, pkts_rate, bytes_rate, mean, median, std, q1, q2, q3, min, and max.

    Parameters
    ----------
    flows:

    Returns
    -------
    features: a list
        stats
    fids: a list
        each value is five-tuple
    """

    features = []
    fids = []
    for fid, pkts in flows:
        sizes = [len(pkt) for pkt in pkts]

        sub_duration = _get_flow_duration(pkts)
        num_pkts = len(sizes)  # number of packets in the flow
        num_bytes = sum(sizes)  # all bytes in sub_duration  sum(len(pkt))
        if sub_duration == 0:
            pkts_rate = 0.0
            bytes_rate = 0.0
        else:
            pkts_rate = num_pkts / sub_duration  # it will be very larger due to the very small sub_duration
            bytes_rate = num_bytes / sub_duration

        q1, q2, q3 = np.quantile(sizes, q=[0.25, 0.5, 0.75])  # q should be [0,1] and q2 is np.median(data)
        base_features = [sub_duration, pkts_rate, bytes_rate, np.mean(sizes), np.std(sizes),
                         q1, q2, q3, np.min(sizes), np.max(sizes)]

        features.append(base_features)

        fids.append(fid)

    return features, fids


def _get_split_interval(flow_durations, q_interval=0.9):
    interval = np.quantile(flow_durations, q=q_interval)

    return interval


def _get_FFT_data(features, fft_bin='', fft_part='real'):
    """Do fft transform of features

    Parameters
    ----------
    features: features

    fft_bin: int
        the dimension of transformed features
    fft_part: str
        'real' or 'real+imaginary' transformation

    Returns
    -------
    fft_features: a list
        transformed fft features
    """
    if fft_part == 'real':  # default
        fft_features = [list(np.real(np.fft.fft(v, n=fft_bin))) for v in features]

    elif fft_part == 'real+imaginary':
        msg = f'{fft_part}'
        raise NotImplementedError(msg)

    else:
        msg = f'fft_part: {fft_part} is not correct, please modify it and retry!'
        raise ValueError(msg)

    return fft_features


class PCAP:
    def __init__(self, pcap_file='xxx.pcap', *, flow_ptks_thres=2, verbose=10, random_state=42):
        """PCAP includes all processing functions of pcaps, such as pcap2flows, flow2features, and label_flows .

        Parameters
        ----------
        pcap_file: str
            a pcap needed to processed.

        flow_ptks_thres: int (default is 2)
            the minimum number of packets of each flow is to control which flow should be kept
            and which one should be discarded. The default value is 2, i.e., all the flows which have less than 2 packets
            are discarded. It must be >= 2.

        verbose: int (default is 1)
            a print level is to control what information should be printed according to the given value.
            The higher the value is, the more info is printed.

        random_state: int
            a value is to make your experiments more reproducible.

        Returns
        -------
            a PCAP instance
        """

        self.pcap_file = pcap_file
        self.flow_ptks_thres = flow_ptks_thres
        self.verbose = verbose
        self.random_state = random_state

    @timing
    def _pcap2flows(self, interval=0, q_interval=0.1, *, tcp_timeout=600, udp_timeout=600):
        """Extract flows from the given pcap and split each flow to subflow by "interval" or "q_interval".
                   It prefers to choose "interval" as the split measure if interval > 0; otherwise, use q_interval to find an interval.
                    q_interval must be in [0, 1]

        Parameters
        ----------
        interval: float (default is 0.)
            an time interval is used to split a flow.

        q_interval: float (default is 0.9)
           a quntile (must be in [0, 1]) is to obtain "interval" from all flow durations.

        tcp_timeout: int (default is 600s)
            a value is to split flow by tcp_timeout.

        udp_timeout: int (default is 600s)
            a value is to split flow by udp_timeout.

        Returns
        -------
        all flows: list
            each element in the list represents a flow, and each flow includes 2 values: flow id (five-tuple) and packets.
        """

        # extract all flows firstly and then split flows to subflows
        flows = _pcap2flows(self.pcap_file, self.flow_ptks_thres, tcp_timeout=tcp_timeout, udp_timeout=udp_timeout,
                            verbose=self.verbose)

        if interval > 0:
            self.interval = interval
        else:
            if q_interval > 0:
                self.q_interval = q_interval

                self.flow_durations = [_get_flow_duration(pkts) for fid, pkts in flows]
                if self.verbose > 3:
                    data_info(np.asarray(self.flow_durations, dtype=float).reshape(-1, 1), name='flow_durations')
                self.interval = _get_split_interval(self.flow_durations, q_interval=self.q_interval)

            else:
                msg = f'q_interval must be in [0, 1]! Current q_interval is {q_interval}.'
                raise ValueError(msg)

        self.flows = _flows2subflows(flows, self.interval, flow_pkts_thres=self.flow_ptks_thres, verbose=self.verbose)

    def pcap2flows(self, interval=0.0, q_interval=0.9, *, tcp_timeout=600, udp_timeout=600):
        """Extract flows from the given pcap and split each flow to subflow by "interval" or "q_interval".
           It prefers to choose "interval" as the split measure if interval > 0; otherwise, use q_interval to find an interval.
            q_interval must be in [0, 1]

        Parameters
        ----------
        interval: float (default is 0.)
            an time interval is used to split a flow.

        q_interval: float (default is 0.9)
           a quntile (must be in [0, 1]) is to obtain "interval" from all flow durations.

        tcp_timeout: int (default is 600s)
            a value is to split flow by tcp_timeout.

        udp_timeout: int (default is 600s)
            a value is to split flow by udp_timeout.
        Returns
        -------
            self
        """
        _, tot_time = self._pcap2flows(interval, q_interval, tcp_timeout=tcp_timeout, udp_timeout=udp_timeout)
        self.pcap2flows.__dict__['tot_time'] = tot_time

    @timing
    def _flow2features(self, feat_type='IAT', *, fft=False, header=False):
        """Extract features from each flow according to feat_type, fft and header.

        Parameters
        ----------
        feat_type: str (default is 'IAT')
            which features do we want to extract from flows

        fft: boolean (default is False)
            if we need fft-features

        header: boolean (default is False)
            if we need header+features

        Returns
        -------
            self
        """
        self.feat_type = feat_type

        num_pkts = [len(pkts) for pkts in self.flows]
        dim = int(np.floor(np.quantile(num_pkts, self.q_interval)))  # use the same q_interval to get the dimension

        if feat_type in ['IAT', 'FFT-IAT']:
            self.dim = dim
            self.features, self.fids = _get_IAT(self.flows)
        elif feat_type in ['SIZE', 'FFT-SIZE']:
            self.dim = dim - 1
            self.features, self.fids = _get_SIZE(self.flows)
        elif feat_type in ['IAT_SIZE', 'FFT-IAT_SIZE']:
            self.dim = 2 * dim - 1
            self.features, self.fids = _get_IAT_SIZE(self.flows)
        elif feat_type in ['STATS']:
            self.dim = 10
            self.features, self.fids = _get_STATS(self.flows)
        else:
            msg = f'feat_type ({feat_type}) is not correct! '
            raise ValueError(msg)

        if fft:
            self.features = _get_FFT_data(self.features, fft_bin=dim)
        else:
            # fix each flow to the same feature dimension (cut off the flow or append 0 to it)
            self.features = [v[:dim] if len(v) > dim else v + [0] * (dim - len(v)) for v in self.features]

        if header:
            _headers = _get_header_features(self.flows)
            h_dim = 8 + dim  # 8 TCP flags
            if fft:
                fft_headers = _get_FFT_data(_headers, fft_bin=h_dim)
                self.features = [h + f for h, f in zip(fft_headers, self.features)]
            else:
                # fix header dimension firstly
                headers = [h[:h_dim] if len(h) > h_dim else h + [0] * (h_dim - len(h)) for h in _headers]
                self.features = [h + f for h, f in zip(headers, self.features)]

        # change list to numpy array
        self.features = np.asarray(self.features, dtype=float)
        if self.verbose > 5:
            print(np.all(self.features >= 0))

    def flow2features(self, feat_type='IAT', *, fft=False, header=False):
        """Extract features from each flow according to feat_type, fft and header.

        Parameters
        ----------
        feat_type: str (default is 'IAT')
            which features do we want to extract from flows

        fft: boolean (default is False)
            if we need fft-features

        header: boolean (default is False)
            if we need header+features

        Returns
        -------
            self
        """
        _, tot_time = self._flow2features(feat_type, fft=fft, header=header)
        self.flow2features.__dict__['tot_time'] = tot_time

    @timing
    def _label_flows(self, label_file='', label=0):
        """label each flow by label_file (only for CICIDS_2017 label_file) or label.
        If you want to parse other label file, you have to override "label_flows()" with your own one.
        (normal=0,and abnormal = 1)

        Parameters
        ----------
        label_file: str
            a file that includes flow labels

        label: int
            if label_file is None, then use "label" to label each flow

        Returns
        -------
        self
        """

        if len(label_file) > 0:
            NORMAL_LABELS = [v.upper() for v in ['benign'.upper(), 'normal'.upper()]]

            # load CSV with pandas
            csv = pd.read_csv(label_file)

            true_labels = {}
            cnt_anomaly = 0
            cnt_nomral = 0

            for i, r in enumerate(csv.index):
                if (self.verbose > 3) and (i % 10000 == 0):
                    print(f"Label CSV {i}th row")
                row = csv.loc[r]
                fid = (str(row[" Source IP"]), str(row[" Destination IP"]), int(row[" Source Port"]),
                       int(row[" Destination Port"]), int(row[" Protocol"]))
                # ensure all 5-tuple flows have same label
                label_i = row[" Label"].upper()
                if label_i in NORMAL_LABELS:
                    label_i = 0
                    cnt_nomral += 1
                else:
                    label_i = 1
                    cnt_anomaly += 1

                # it will overwrite the previous label for the same fid.
                true_labels[fid] = label_i

            # label flows with ture_labels
            new_labels = []
            not_existed_fids = []
            new_flows = []
            for i, (fid, pkts) in enumerate(self.flows):
                if fid in true_labels.keys():
                    new_labels.append(true_labels[fid])
                    new_flows.append((fid, pkts))
                else:
                    # the fid does not exist in labels.csv
                    not_existed_fids.append(fid)
            if self.verbose > 3:
                print(
                    f'Number of labelled flows: {len(new_labels)}; number of not existed flows: {len(not_existed_fids)}')

            self.labels = new_labels
            self.flows = new_flows
        else:
            self.labels = [label] * len(self.flows)

        self.labels = np.asarray(self.labels, dtype=int)

    def label_flows(self, label_file=None, label=0):
        """label each flow by label_file (only for CICIDS_2017 label_file) or label.
        If you want to parse other label file, you have to override "label_flows()" with your own one.
        (normal=0,and abnormal = 1)

        Parameters
        ----------
        label_file: str
            a file that includes flow labels

        label: int
            if label_file is None, then use "label" to label each flow

        Returns
        -------
        self
        """
        _, tot_time = self._label_flows(label_file, label)
        self.label_flows.__dict__['tot_time'] = tot_time


def random_select_flows(flows, labels, experiment='ind', random_state=42, pcap_file=''):
    """ obtain normal and anomaly flows and drop the rest.

    Parameters
    ----------
    flows
    labels
    experiment
    random_state

    Returns
    -------

    """
    # if experiment.upper() in ['INDV', 'MIX']:  # for indv and mix use all of data.
    #     return flows, labels

    cnt_normal = 0
    cnt_anomaly = 0
    others = []
    print(Counter(labels))
    for i, label_i in enumerate(labels):
        if label_i.upper() in ['NORMAL', 'BENIGN']:
            cnt_normal += 1
        elif label_i.upper() in ['BOT', 'ANOMALY', 'MALICIOUS']:
            cnt_anomaly += 1
        else:
            others.append(label_i)

    print(
        f'cnt_normal: {cnt_normal}, cnt_anomaly: {cnt_anomaly}, cnt_others: {len(others)}, Counter(others): {Counter(others)}')
    get_all_flows_flg = True  # True: use all of flows samples, False: random select part of flow samples.
    # if 'DS50_MAWI_WIDE' in pcap_file or 'DS40_CTU_IoT' in pcap_file:
    #     CNT_ANOMALY = 400
    if 'DS60_UChi_IoT' in pcap_file or 'DS20_PU_SMTV' in pcap_file:
        CNT_ANOMALY = 600
    elif 'DS10_UNB_IDS' in pcap_file:
        if cnt_normal > int(7 / 3 * cnt_anomaly):  # normal: anomaly = 7:3
            CNT_ANOMALY = cnt_anomaly
        else:
            CNT_ANOMALY = int(cnt_normal * 3 / 7)
    else:
        CNT_ANOMALY = 400

    if cnt_anomaly < CNT_ANOMALY:
        part_anomaly_thres = cnt_anomaly
    else:
        part_anomaly_thres = CNT_ANOMALY
    if cnt_anomaly < 10:
        print(f'skip cnt_anomaly(={part_anomaly_thres}) < 10')
        print(f'cnt_normal: {cnt_normal}, cnt_anomaly: {cnt_anomaly}=> part_anomaly_thres: {part_anomaly_thres}')
        return -1

    part_normal_thres = 10000 + part_anomaly_thres  # only random get 20000 normal samples.
    if cnt_normal > part_normal_thres or cnt_anomaly > part_anomaly_thres:  # if cnt_normal > 20000 and cnt_anomaly > 150:
        get_all_flows_flg = False  # make all data have the same size
        # break # if has break here, it only print part of flows in cnt_normal

    print(f'before, len(flows): {len(flows)}, len(lables): {len(labels)}, get_all_flows_flg: {get_all_flows_flg}, '
          f'cnt_normal: {cnt_normal}, cnt_anomaly: {cnt_anomaly}')

    if not get_all_flows_flg:
        c = list(zip(flows, labels))
        flows_shuffle, labels_shuffle = zip(*shuffle(c, random_state=random_state))
        cnt_normal = 0
        cnt_anomaly = 0
        flows = []
        labels = []
        for i, (flows_i, label_i) in enumerate(zip(flows_shuffle, labels_shuffle)):
            if label_i.upper() in ['NORMAL', 'BENIGN']:
                cnt_normal += 1
                if cnt_normal <= part_normal_thres:
                    flows.append(flows_i)
                    labels.append(label_i)
            elif label_i.upper() in ['BOT', 'ANOMALY', 'MALICIOUS']:
                cnt_anomaly += 1
                if cnt_anomaly <= part_anomaly_thres:
                    flows.append(flows_i)
                    labels.append(label_i)

            if cnt_normal > part_normal_thres and cnt_anomaly > part_anomaly_thres:
                break
        else:
            pass
    print(f'after: len(flows): {len(flows)}, len(lables): {len(labels)}, get_all_flows_flg: {get_all_flows_flg}, '
          f'cnt_normal: {min(cnt_normal, part_normal_thres)}, cnt_anomaly: {min(cnt_anomaly, part_anomaly_thres)}')

    return flows, labels


def handle_large_time_diff(start_time, end_time, interval=0.1, max_num=10000):
    """

    :param start_time:
    :param end_time:
    :param interval:
    :param max_num: the maximum number of 0 inserted to the features
    :return:
    """
    if start_time >= end_time:
        raise ValueError('start_time >= end_time')

    num_intervals = int((end_time - start_time) // interval)
    # print(f'num_intervals: {num_intervals}')
    if num_intervals > max_num:
        # print(
        #     f'num_intervals with 0: {num_intervals} = (end_time({end_time}) - start_time({start_time}))/(sampling_rate: {interval})'
        #     f', only keep: {max_num}')
        num_intervals = max_num
    features_lst = [0] * num_intervals

    start_time = start_time + num_intervals * interval

    return features_lst, start_time


def sampling_packets(flow, sampling_type='rate', sampling=5, sampling_feature='samp_num', random_state=42):
    """

    :param flow:
    :param sampling_type:
    :param sampling:
    :return:
    """
    # the flows should be a deep copy of original flows. copy.deepcopy(flow)

    fid, times, sizes = flow
    sampling_data = []

    if sampling_type == 'rate':  # sampling_rate within flows.

        # The length in time of this small window is what we’re calling sampling rate.
        # features obtained on sampling_rate = 0.1 means that:
        #  1) split each flow into small windows, each window has 0.1 duration (the length in time of each small window)
        #  2) obtain the number of packets in each window (0.1s).
        #  3) all the number of packets in each window make up of the features.

        if sampling_feature in ['samp_num', 'samp_size']:
            features = []
            samp_sub = 0
            # print(f'len(times): {len(times)}, duration: {max(times)-min(times)}, sampling: {sampling}, num_features: {int(np.round((max(times)-min(times))/sampling))}')
            for i in range(len(times)):  # times: the arrival time of each packet
                if i == 0:
                    current = times[0]
                    if sampling_feature == 'samp_num':
                        samp_sub = 1
                    elif sampling_feature == 'samp_size':
                        samp_sub = sizes[0]
                    continue
                if times[i] - current <= sampling:  # interval
                    if sampling_feature == 'samp_num':
                        samp_sub += 1
                    elif sampling_feature == 'samp_size':
                        samp_sub += sizes[i]
                    else:
                        print(f'{sampling_feature} is not implemented yet')
                else:  # if times[i]-current > sampling:    # interval
                    current += sampling
                    features.append(samp_sub)
                    # the time diff between times[i] and times[i-1] will be larger than mutli-samplings
                    # for example, times[i]=10.0s, times[i-1]=2.0s, sampling=0.1,
                    # for this case, we should insert int((10.0-2.0)//0.1) * [0]
                    num_intervals = int(np.floor((times[i] - current) // sampling))
                    if num_intervals > 0:
                        num_intervals = min(num_intervals, 500)
                        features.extend([0] * num_intervals)
                        current += num_intervals * sampling
                    # if current + sampling <= times[i]:  # move current to the nearest position to time[i]
                    #     feat_lst_tmp, current = handle_large_time_diff(start_time=current, end_time=times[i],
                    #                                                    interval=sampling)
                    # features.extend(feat_lst_tmp)
                    if len(features) > 500:  # avoid num_features too large to excess the memory.
                        return fid, features[:500]

                    # samp_sub = 1  # includes the time[i] as a new time interval
                    if sampling_feature == 'samp_num':
                        samp_sub = 1
                    elif sampling_feature == 'samp_size':
                        samp_sub = sizes[i]

            if samp_sub > 0:  # handle the last sub period in the flow.
                features.append(samp_sub)

            return fid, features
        else:
            raise ValueError(f'sampling_feature: {sampling_feature} is not implemented.')
    else:
        raise ValueError(f'sample_type: {sampling_type} is not implemented.')


def _flows_to_samps(flows, sampling_type='rate', sampling=None,
                    sampling_feature='samp_num',
                    verbose=True):
    ''' sampling packets in flows
    '''
    # the flows should be a deep copy of original flows. copy.deepcopy(flows)
    # flows = copy.deepcopy(flows_lst)

    # samp_flows = []
    features = []
    features_header = []
    for fid, times, pkts in flows:
        sizes = [len(pkt) for pkt in pkts]
        if sampling_feature == 'samp_num_size':
            samp_features = []
            samp_fid_1, samp_features_1 = sampling_packets((fid, times, sizes), sampling_type=sampling_type,
                                                           sampling=sampling, sampling_feature='samp_num')

            samp_fid_2, samp_features_2 = sampling_packets((fid, times, sizes), sampling_type=sampling_type,
                                                           sampling=sampling, sampling_feature='samp_size')
            for i in range(len(samp_features_1)):
                if len(samp_features) > 500:
                    break
                samp_features.extend([samp_features_1[i], samp_features_2[i]])
            samp_fid = samp_fid_1
        else:
            samp_fid, samp_features = sampling_packets((fid, times, sizes), sampling_type=sampling_type,
                                                       sampling=sampling, sampling_feature=sampling_feature)

        features.append((samp_fid, samp_features))  # (fid, np.array())

    # if header:
    #     head_len = int(np.quantile([len(head) for (fid, head) in features_header], q=q_iat))
    #     for i, (fid_head, fid_feat) in enumerate(list(zip(features_header, features))):
    #         fid, head = fid_head
    #         fid, feat = fid_feat
    #         if len(head) > head_len:
    #             head = head[:head_len]
    #         else:
    #             head += [0] * (head_len - len(head))
    #         features[i] = (fid, np.asarray(head + list(feat)))

    if verbose:  # for debug
        show_len = 10  # only show the first 20 difference
        samp_lens = np.asarray([len(samp_features) for (fid, samp_features) in features])[:show_len]
        raw_lens = np.asarray([max(times) - min(times) for (fid, times, sizes) in flows])[:show_len]
        print(f'(flow duration, num_windows), when sampling_rate({sampling})):\n{list(zip(raw_lens, samp_lens))}')

    return features


def _load_labels_and_label_flows_by_data(fids_labels, features='', label_file_type='CTU-IoT-23'):
    """ label features by fids_labels

    Parameters
    ----------
    fids_labels
    features
    label_file_type

    Returns
    -------

    """

    labels = []
    for i, (fid, feat) in enumerate(features):
        flg = False
        for j, (fid_j, label_j) in enumerate(fids_labels):
            if fid == fid_j:
                flg = True
                labels.append(label_j)
                break

        if not flg:
            labels.append('None')
    print(f'len(labels): {len(labels)}')

    return labels


def process_CIC_IDS_2017(label_file, time_range=['start', 'end'], output_file='_reduced.txt'):
    """ timezone: ADT in CIC_IDS_2017 label.csv

    Parameters
    ----------
    label_file
    time_range
    output_file

    Returns
    -------

    """
    with open(output_file, 'w') as out_f:
        start = 0
        i = 0
        start_flg = True
        end = 0
        max_sec = -1
        min_sec = -1
        with open(label_file, 'r') as in_f:
            line = in_f.readline()
            flg = False
            while line:
                if line.startswith("Flow"):
                    line = in_f.readline()
                    continue
                arr = line.split(',')
                # time
                # print(arr[6])
                time_str = datetime.strptime(arr[6], "%d/%m/%Y %H:%M")
                time_str = convert_datetime_timezone(str(time_str), tz1='Canada/Atlantic', tz2='UTC')
                ts = time_string_to_seconds(str(time_str), '%Y-%m-%d %H:%M:%S')
                if start_flg:
                    print(i, ts, start)
                    start = ts
                    min_sec = start
                    start_flg = False
                else:
                    if ts > end:
                        end = ts
                    if ts < min_sec:
                        min_sec = ts
                    if ts > max_sec:
                        max_sec = ts
                if ts > time_range[0] and ts < time_range[1]:
                    out_f.write(line.strip('\n') + '\n')
                # if ts > time_range[1]:
                #     break

                line = in_f.readline()
                i += 1
        print(start, end, time_range, i, min_sec, max_sec)

    return output_file


def label_flows(flows, pth_label='xxx.csv'):
    """
    1. The number of flows in pth_label is more than flows in pcap, is it possible?
    2. Some flow appears in pth_label, but not in flows, or vice versa, is it possible?

    Parameters
    ----------
    flows
    pth_label

    Returns
    -------

    """
    NORMAL_LABELS = [v.upper() for v in ['benign', 'normal']]
    # ANOMALY_LABELS = [v.upper() for v in ['ANOMALY', 'Malicious', 'FTP-PATATOR', 'SSH-PATATOR',
    #                                       'DoS slowloris', 'DoS Slowhttptest', 'DoS Hulk', 'DoS GoldenEye',
    #                                       'Heartbleed',
    #                                       'Web Attack – Brute Force', 'Web Attack – XSS',
    #                                       'Web Attack – Sql Injection', 'Infiltration',
    #                                       'Bot', 'PortScan', 'DDoS']]

    NORMAL = 'normal'.upper()
    ABNORMAL = 'abnormal'.upper()

    # load CSV with pandas
    csv = pd.read_csv(pth_label)

    labels = {}  # {fid:(1, 0)} # 'normal':1, 'abnormal':0
    cnt_anomaly = 0
    cnt_nomral = 0

    for i, r in enumerate(csv.index):
        if i % 10000 == 0:
            print("Label CSV row {}".format(i))
        row = csv.loc[r]
        # parse 5-tuple flow ID
        # When you merge two csvs with headers, the file includes 'LABEL' means this line is the header
        # so just skip it
        if 'LABEL' in row[" Label"].upper():
            continue
        fid = (str(row[" Source IP"]), str(row[" Destination IP"]), int(row[" Source Port"]),
               int(row[" Destination Port"]), int(row[" Protocol"]))
        # ensure all 5-tuple flows have same label
        label_i = row[" Label"].upper()
        if label_i in NORMAL_LABELS:
            label_i = NORMAL
            cnt_nomral += 1
        else:
            label_i = ABNORMAL
            cnt_anomaly += 1

        if fid in labels.keys():
            labels[fid][label_i] += 1  # labels = {fid: {'normal':1, 'abnormal': 1}}
        else:
            v = 1 if label_i == NORMAL else 0
            labels[fid] = {NORMAL: v, ABNORMAL: 1 - v}

    # decide the true label of each fid
    conflicts = {}
    mislabels = {NORMAL: 0, ABNORMAL: 0}
    for fid, value in labels.items():
        if value[ABNORMAL] > 0 and value[NORMAL] > 0:
            conflicts[fid] = value

        if value[NORMAL] > value[ABNORMAL]:
            labels[fid] = NORMAL
            mislabels[NORMAL] += value[ABNORMAL]  # label 'abnormal' as 'normal'
        else:
            labels[fid] = ABNORMAL
            mislabels[ABNORMAL] += value[NORMAL]  # label 'normal' as 'abnormal'

    # for debug
    an = 0
    na = 0
    for fid, value in conflicts.items():
        if value[NORMAL] > value[ABNORMAL]:
            an += value[ABNORMAL]
        else:
            na += value[NORMAL]

    print(f'label_csv: cnt_normal: {cnt_nomral}, cnt_anomaly: {cnt_anomaly}, Unique labels: {len(labels.keys())}, '
          f'Counter(labels.values()),{Counter(labels.values())}, conflicts: {len(conflicts.keys())}'
          f', mislabels = {mislabels},  abnormal labeled as normal: {an}, normal labeled as abnormal: {na}')

    # obtain the labels of the corresponding features
    new_labels = []
    not_existed_fids = []
    new_fids = []
    for i, (fid, pkt_time, pkt) in enumerate(flows):
        if i == 0:
            print(f'i=0: fid: {fid}, list(labels.keys())[0]: {list(labels.keys())[0]}')
        if fid in labels.keys():
            new_labels.append(labels[fid])
            new_fids.append(fid)
        else:
            not_existed_fids.append(fid)
            new_fids.append('None')
            new_labels.append('None')  # the fid does not exist in labels.csv

    print(f'***{len(not_existed_fids)} (unique fids: {len(set(not_existed_fids))}) flows do not exist in {pth_label},'
          f'Counter(not_existed_fids)[:10]{list(Counter(not_existed_fids))[:10]}')
    print(f'len(new_labels): {len(new_labels)}, unique labels of new_labels: {Counter(new_labels)}')
    return (new_fids, new_labels)
