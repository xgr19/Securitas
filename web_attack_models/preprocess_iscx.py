import argparse
import os
import pickle
import random

import dpkt

from iscx_data import PROTOCOLS


NOISE_PORTS = {137, 5355, 53, 123, 5353, 1900, 138, 17500, 67}


def ip_to_str(raw_ip):
    return '.'.join(map(str, map(int, raw_ip)))


def flow_key(src, dst, proto, sport, dport):
    return f'{src} {dst} {proto} {sport} {dport}'


def collect_bidirectional_flows(raw_data_dir, max_flows_per_class=10000, max_packets_per_flow=1000):
    flows_by_protocol = {}

    for protocol in PROTOCOLS:
        protocol_dir = os.path.join(raw_data_dir, protocol)
        pcap_paths = [
            os.path.join(protocol_dir, name)
            for name in os.listdir(protocol_dir)
            if 'pcap' in name
        ]
        pcap_paths.sort()

        flows = {}
        known_forward_keys = set()
        for pcap_path in pcap_paths:
            print(f'processing pcap file: {pcap_path}')
            with open(pcap_path, 'rb') as fh:
                pcap = dpkt.pcap.Reader(fh)
                if pcap.datalink() != dpkt.pcap.DLT_EN10MB:
                    raise ValueError(f'unsupported data link in {pcap_path}')

                for ts, buff in pcap:
                    eth = dpkt.ethernet.Ethernet(buff)
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue
                    ip = eth.data
                    if not isinstance(ip.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                        continue
                    if ip.data.sport in NOISE_PORTS or ip.data.dport in NOISE_PORTS:
                        continue

                    if len(flows) >= max_flows_per_class:
                        break

                    src = ip_to_str(ip.src)
                    dst = ip_to_str(ip.dst)
                    forward = flow_key(src, dst, ip.p, ip.data.sport, ip.data.dport)
                    reverse = flow_key(dst, src, ip.p, ip.data.dport, ip.data.sport)

                    if forward in known_forward_keys:
                        if len(flows[forward]) < max_packets_per_flow:
                            flows[forward].append([ts, len(ip.data), 1])
                    elif reverse in known_forward_keys:
                        if len(flows[reverse]) < max_packets_per_flow:
                            flows[reverse].append([ts, len(ip.data), -1])
                    else:
                        known_forward_keys.add(forward)
                        flows[forward] = [[ts, len(ip.data), 1]]

        flows_by_protocol[protocol] = flows
        total_packets = sum(len(pkts) for pkts in flows.values())
        print(f'{protocol}: {len(flows)} flows, {total_packets} packets')

    return flows_by_protocol


def flows_to_sessions(flows_by_protocol, train_ratio=0.8, min_packets=15, sequence_length=1000,
                      shuffle_seed=1024, split_seed=None):
    session_dict = {'train': {}, 'test': {}}
    split_rng = random if split_seed is None else random.Random(split_seed)

    for protocol in PROTOCOLS:
        session_dict['train'][protocol] = []
        session_dict['test'][protocol] = []
        keys = list(flows_by_protocol[protocol].keys())
        random.Random(shuffle_seed).shuffle(keys)

        for key in keys:
            pkts = [list(pkt) for pkt in flows_by_protocol[protocol][key]]
            if len(pkts) < min_packets:
                continue

            while len(pkts) < sequence_length:
                pkts.append([0, 0, 1])
            if len(pkts) > sequence_length:
                pkts = pkts[:sequence_length]

            for pkt in pkts:
                pkt[1] = min(pkt[1], 1500)

            split = 'train' if split_rng.random() < train_ratio else 'test'
            session_dict[split][protocol].append(pkts)

    return session_dict


def main():
    parser = argparse.ArgumentParser(description='Generate ISCX sessions directly from raw pcap files.')
    parser.add_argument('--raw-data-dir', required=True, help='Directory containing one subdirectory per ISCX protocol.')
    parser.add_argument('--output', default='data/iscx_session.pkl')
    parser.add_argument('--train-ratio', type=float, default=0.8)
    parser.add_argument('--shuffle-seed', type=int, default=1024)
    parser.add_argument('--split-seed', type=int, default=None)
    args = parser.parse_args()

    flows = collect_bidirectional_flows(args.raw_data_dir)
    sessions = flows_to_sessions(
        flows,
        train_ratio=args.train_ratio,
        shuffle_seed=args.shuffle_seed,
        split_seed=args.split_seed,
    )

    os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
    with open(args.output, 'wb') as fh:
        pickle.dump(sessions, fh)
    print(args.output)


if __name__ == '__main__':
    main()
