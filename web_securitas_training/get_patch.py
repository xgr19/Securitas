import argparse
import copy
import os
import random

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F


EMBEDDING_SIZE = 32
GLOBAL_NUMBER_CHOICE = [0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88]


class Mind(nn.Module):
    def __init__(self, space):
        super().__init__()
        input_space = copy.deepcopy(space)
        input_space[0] = 10
        self.embedding_list = nn.ModuleList([
            nn.Embedding(input_space[i], EMBEDDING_SIZE) for i in range(len(input_space))
        ])
        self.lstm = nn.LSTM(EMBEDDING_SIZE, EMBEDDING_SIZE, batch_first=True)
        self.linear_list = nn.ModuleList([
            nn.Linear(EMBEDDING_SIZE, space[i]) for i in range(len(space))
        ])
        self.stage = 0
        self.hidden = None

    def forward(self, x):
        x = self.embedding_list[self.stage](x)
        self.lstm.flatten_parameters()
        x, self.hidden = self.lstm(x, self.hidden)
        return self.linear_list[self.stage](x.view(x.size(0), -1))

    def increment_stage(self):
        self.stage += 1

    def reset(self):
        self.stage = 0
        self.hidden = None


def select_combo(model, space, device):
    state = torch.from_numpy(np.array([0, 1, 2, 3, 4, 5, 6, 7]).reshape(8, 1)).long().to(device)
    combo = []
    log_p_combo = []
    for _ in range(len(space)):
        p_a = F.softmax(model(state), dim=1)
        action = torch.argmax(p_a, dim=1).unsqueeze(-1)
        combo.append(action)
        log_p_combo.append(action)
        state = action
        model.increment_stage()
    return torch.cat(combo, dim=1), torch.cat(log_p_combo, dim=1)


def read_policy(policy_path, space, device):
    mind_model = Mind(space)
    mind_model.load_state_dict(torch.load(policy_path, map_location='cpu'))
    mind_model = mind_model.to(device).eval()
    combo, _ = select_combo(mind_model, space, device)
    return combo.cpu().numpy()


def write_p4(all_combo, patch_length, output_path, max_patch_num, split_ratio):
    if not 0.0 <= split_ratio <= 1.0:
        raise ValueError('--split-ratio/--fragment-ratio must be in [0, 1].')

    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    with open(output_path, 'w') as f:
        print('', file=f)
        print('const entries = {', file=f)
        print('    // patch_idx, pkt_cnt      mirrored_ip_payload_len (should be 8-unit!!)', file=f)

        combo_idx = list(range(all_combo.shape[0]))
        random.shuffle(combo_idx)

        max_patch_num = min(max_patch_num, all_combo.shape[0])
        for idx in range(max_patch_num):
            combo = all_combo[combo_idx[idx]]
            for dim1 in range(patch_length):
                choice = int(combo[dim1])
                if choice == 0:
                    continue

                action = 'ac_should_fragment' if random.random() < split_ratio else 'ac_should_TTL'
                print(
                    '    (%d, %7d): %s(%d);'
                    % (idx, dim1 + 1, action, GLOBAL_NUMBER_CHOICE[choice]),
                    file=f,
                )

        print('}', file=f)


def main():
    parser = argparse.ArgumentParser(
        description='Export Securitas policy-network checkpoints to a P4 const entries block.'
    )
    parser.add_argument('--dataset-name', default='ISCX')
    parser.add_argument('--patch-length', type=int, default=204)
    parser.add_argument(
        '--policy-path',
        action='append',
        default=None,
        help='Path to a best_mind.pth file. Can be passed multiple times.',
    )
    parser.add_argument(
        '--policy-dir',
        default='outputs/APP_net_204_split_88_0.7_0.6',
        help='Used when --policy-path is not provided; expects best_mind.pth inside this directory.',
    )
    parser.add_argument('--output-dir', default='patch_p4_code')
    parser.add_argument('--output-name', default=None)
    parser.add_argument('--max-patch-num', type=int, default=1)
    parser.add_argument(
        '--split-ratio',
        '--fragment-ratio',
        dest='split_ratio',
        type=float,
        default=0.7,
        help=(
            'Probability that each non-zero action is exported as '
            'ac_should_fragment; otherwise ac_should_TTL. This is Pr in the '
            'paper, whose default setting is 0.7.'
        ),
    )
    parser.add_argument('--device', choices=['cpu', 'cuda'], default='cpu')
    parser.add_argument('--gpu', type=int, default=None)
    args = parser.parse_args()

    device = torch.device(args.device)
    if args.gpu is not None:
        torch.cuda.set_device(args.gpu)
        device = torch.device('cuda')

    random.seed(2023)
    space = [len(GLOBAL_NUMBER_CHOICE) for _ in range(args.patch_length)]
    policy_paths = args.policy_path or [os.path.join(args.policy_dir, 'best_mind.pth')]

    all_combo = np.empty((0, args.patch_length))
    for policy_path in policy_paths:
        combo = read_policy(policy_path, space, device)
        all_combo = np.concatenate((all_combo, combo), axis=0)

    print(all_combo.shape)
    output_name = args.output_name or '%s_%d.p4' % (args.dataset_name, args.patch_length)
    output_path = os.path.join(args.output_dir, output_name)
    write_p4(all_combo, args.patch_length, output_path, args.max_patch_num, args.split_ratio)
    print(output_path)


if __name__ == '__main__':
    main()
