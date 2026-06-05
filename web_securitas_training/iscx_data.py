import numpy as np
import torch


PROTOCOLS = ['email', 'chat', 'streaming_multimedia', 'file_transfer', 'voip', 'p2p']
MAX_PACKET_SIZE = 1518
SEQUENCE_LENGTH = 512
MIN_PACKETS = 15


class ISCXDataset(torch.utils.data.Dataset):
    def __init__(self, x, label, direction):
        self.x = x
        self.label = label
        self.direction = direction

    def __len__(self):
        return len(self.x)

    def __getitem__(self, idx):
        return self.x[idx], self.label[idx], self.direction[idx]


def load_epoch_data(flow_dict, split='train'):
    split_dict = flow_dict[split]
    x, direction, label = [], [], []

    for protocol in PROTOCOLS:
        for session in split_dict[protocol]:
            flow = []
            flow_direction = []
            for pkt in session:
                if pkt[1] == 0:
                    continue
                if pkt[2] > 0:
                    flow.append(pkt[1])
                    flow_direction.append(1)
                elif pkt[2] < 0:
                    flow.append(pkt[1])
                    flow_direction.append(-1)

            if len(flow) < MIN_PACKETS:
                continue

            while len(flow) < SEQUENCE_LENGTH:
                flow.append(0)
                flow_direction.append(0)
            if len(flow) > SEQUENCE_LENGTH:
                flow = flow[:SEQUENCE_LENGTH]
                flow_direction = flow_direction[:SEQUENCE_LENGTH]

            x.append(flow)
            direction.append(flow_direction)
            label.append(PROTOCOLS.index(protocol))

    return np.array(x), np.array(label)[:, np.newaxis], np.array(direction)


def clean_data(data, label, direction):
    del_list = []
    for dim1 in range(data.shape[0]):
        for dim2 in range(data.shape[1]):
            if data[dim1][dim2] > MAX_PACKET_SIZE:
                del_list.append(dim1)
                break

    return (
        np.delete(data, del_list, axis=0),
        np.delete(label, del_list, axis=0),
        np.delete(direction, del_list, axis=0),
    )


def collate_securitas(insts):
    x, label, direction = list(zip(*insts))
    return (
        torch.LongTensor(np.array(x)),
        torch.LongTensor(np.array(label)).contiguous().view(-1),
        torch.LongTensor(np.array(direction)),
    )
