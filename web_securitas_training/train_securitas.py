import argparse
import os
import pickle
import random
import time

import numpy as np
import torch

from BSCAttack_agents import agent
from iscx_data import ISCXDataset, clean_data, collate_securitas, load_epoch_data
from model import APPNet
from utils import test_epoch


def parse_loss_weights(raw):
    values = [float(item) for item in raw.split(',')]
    if len(values) != 3:
        raise argparse.ArgumentTypeError('loss weights must have exactly 3 comma-separated values')
    return values


def set_seed(seed):
    np.random.seed(seed)
    torch.manual_seed(seed)
    random.seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False


def set_device(gpu):
    if gpu is not None:
        torch.cuda.set_device(gpu)
    return torch.device('cuda' if torch.cuda.is_available() else 'cpu')


def make_loader(flow_dict, split, batch_size, shuffle):
    x, label, direction = load_epoch_data(flow_dict, split)
    x, label, direction = clean_data(x, label, direction)
    return torch.utils.data.DataLoader(
        ISCXDataset(x=x, label=label, direction=direction),
        num_workers=0,
        collate_fn=collate_securitas,
        batch_size=batch_size,
        shuffle=shuffle,
    )


def main():
    parser = argparse.ArgumentParser(description='Train Securitas policy on ISCX with APP-Net.')
    parser.add_argument('--data', default='data/iscx_session.pkl')
    parser.add_argument('--checkpoint', default='models/APP_net.pth')
    parser.add_argument('--output-root', default='outputs')
    parser.add_argument('--output-dir', default=None)
    parser.add_argument('--patch-length', type=int, default=204)
    parser.add_argument('--split-ratio', type=float, default=0.7)
    parser.add_argument('--loss-weights', type=parse_loss_weights, default=[0.6, 0.2, 0.2])
    parser.add_argument('--epochs', type=int, default=10000)
    parser.add_argument('--steps', type=int, default=1)
    parser.add_argument('--lr', type=float, default=0.001)
    parser.add_argument('--batch-size', type=int, default=512)
    parser.add_argument('--seed', type=int, default=2023)
    parser.add_argument('--gpu', type=int, default=None)
    args = parser.parse_args()

    set_seed(args.seed)
    device = set_device(args.gpu)
    if device.type != 'cuda':
        raise RuntimeError('Securitas policy training currently requires CUDA.')

    weight_tag = str(args.loss_weights[0]).rstrip('0').rstrip('.')
    output_name = args.output_dir or f'APP_net_{args.patch_length}_split_88_{args.split_ratio}_{weight_tag}'
    model_save_dir = os.path.join(args.output_root, output_name)
    os.makedirs(model_save_dir, exist_ok=True)
    results_path = os.path.join(model_save_dir, 'results.txt')

    model = APPNet().to(device)
    checkpoint = torch.load(args.checkpoint, map_location='cpu')
    state_dict = checkpoint['model'] if isinstance(checkpoint, dict) and 'model' in checkpoint else checkpoint
    model.load_state_dict(state_dict)
    model.eval()

    with open(args.data, 'rb') as pkl:
        flow_dict = pickle.load(pkl)

    training_data = make_loader(flow_dict, 'train', args.batch_size, True)
    test_data = make_loader(flow_dict, 'test', args.batch_size, False)

    with open(results_path, 'w') as log:
        log.write('start time = %s\n' % (time.asctime(time.localtime(time.time()))))
        acc, avg_acc = test_epoch(model, test_data)
        log.write('normal test acc = %.3f, avg_acc = %.3f\n' % (acc * 100, avg_acc * 100))
        log.flush()

        agent.attack(
            model=model,
            training_data=training_data,
            test_data=test_data,
            lr=args.lr,
            rl_batch=args.batch_size,
            steps=args.steps,
            epochs=args.epochs,
            f=log,
            patch_len=args.patch_length,
            model_save_dir=model_save_dir + os.sep,
            loss_weights=args.loss_weights,
            split_ratio=args.split_ratio,
        )

    print(model_save_dir)


if __name__ == '__main__':
    main()
