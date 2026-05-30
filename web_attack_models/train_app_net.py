import argparse
import os
import pickle
import time

import numpy as np
import torch
import torch.nn.functional as F
import torch.optim as optim
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from tqdm import tqdm, trange

from iscx_data import ISCXDataset, clean_data, collate_attack_model, load_epoch_data
from model import APPNet


def count_parameters(model):
    return sum(p.numel() for p in model.parameters() if p.requires_grad) / 1e6


def set_device(gpu):
    if gpu is not None:
        torch.cuda.set_device(gpu)
    return torch.device('cuda' if torch.cuda.is_available() else 'cpu')


def make_loader(flow_dict, split, batch_size, shuffle):
    x, direction, label = load_epoch_data(flow_dict, split)
    x, direction, label = clean_data(x, direction, label)
    return torch.utils.data.DataLoader(
        ISCXDataset(x=x, label=label),
        num_workers=0,
        collate_fn=collate_attack_model,
        batch_size=batch_size,
        shuffle=shuffle,
    ), label


def cal_loss(pred, gold):
    gold = gold.contiguous().view(-1)
    loss = F.cross_entropy(pred, gold)
    pred_label = F.softmax(pred, dim=-1).max(1)[1]
    acc = pred_label.eq(gold).sum().item() / pred_label.shape[0]
    return loss, acc * 100


def train_epoch(model, training_data, optimizer, device):
    model.train()
    total_loss = []
    total_acc = []
    for src_seq, gold in tqdm(training_data, mininterval=2, desc='  - (Training)   ', leave=False):
        src_seq, gold = src_seq.to(device), gold.to(device)
        optimizer.zero_grad()
        pred = model(src_seq)
        loss_per_batch, acc_per_batch = cal_loss(pred, gold)
        loss_per_batch.backward()
        optimizer.step()
        total_loss.append(loss_per_batch.item())
        total_acc.append(acc_per_batch)
    return sum(total_loss) / len(total_loss), sum(total_acc) / len(total_acc)


def test_epoch(model, test_data, device):
    model.eval()
    total_acc = []
    total_pred = []
    total_time = []
    with torch.no_grad():
        for src_seq, gold in tqdm(test_data, mininterval=2, desc='  - (Testing)   ', leave=False):
            src_seq, gold = src_seq.to(device), gold.to(device)
            gold = gold.contiguous().view(-1)
            if device.type == 'cuda':
                torch.cuda.synchronize()
            start = time.time()
            pred = model(src_seq)
            if device.type == 'cuda':
                torch.cuda.synchronize()
            end = time.time()
            pred_label = F.softmax(pred, dim=-1).max(1)[1]
            acc = pred_label.eq(gold).sum().item() * 100 / pred_label.shape[0]
            total_acc.append(acc)
            total_pred.extend(pred_label.long().tolist())
            total_time.append(end - start)
    return sum(total_acc) / len(total_acc), total_pred, sum(total_time) / len(total_time)


def main():
    parser = argparse.ArgumentParser(description='Train APP-Net on ISCX session data.')
    parser.add_argument('--data', default='data/iscx_session.pkl')
    parser.add_argument('--checkpoint', default='models/APP_net.pth')
    parser.add_argument('--log-dir', default='APP_net_training')
    parser.add_argument('--epochs', type=int, default=2000)
    parser.add_argument('--batch-size', type=int, default=512)
    parser.add_argument('--lr', type=float, default=0.001)
    parser.add_argument('--gpu', type=int, default=None)
    args = parser.parse_args()

    device = set_device(args.gpu)
    os.makedirs(os.path.dirname(args.checkpoint) or '.', exist_ok=True)
    os.makedirs(args.log_dir, exist_ok=True)
    results_path = os.path.join(args.log_dir, 'results.txt')
    metric_path = os.path.join(args.log_dir, 'metric.txt')
    cm_path = os.path.join(args.log_dir, 'cm.pkl')

    with open(args.data, 'rb') as fh:
        flow_dict = pickle.load(fh)

    model = APPNet().to(device)
    optimizer = optim.Adam(filter(lambda x: x.requires_grad, model.parameters()), lr=args.lr)
    best_test_acc = 0

    with open(results_path, 'w') as log:
        log.write('start time = %s\n' % (time.asctime(time.localtime(time.time()))))
        log.write('Train Loss Time Test\n')
        log.write('param = %.4fMB\n' % (count_parameters(model)))
        log.flush()

        for _ in trange(args.epochs, mininterval=1, desc='  - (Training Epochs)   ', leave=False):
            training_data, _ = make_loader(flow_dict, 'train', args.batch_size, True)
            train_loss, train_acc = train_epoch(model, training_data, optimizer, device)

            test_data, test_label = make_loader(flow_dict, 'test', args.batch_size, False)
            test_acc, pred, test_time = test_epoch(model, test_data, device)

            flat_test_label = np.asarray(test_label).reshape(-1)

            with open(metric_path, 'w') as metric_log:
                metric_log.write('PRE REC F1\n')
                p, r, fscore, _ = precision_recall_fscore_support(flat_test_label, pred, zero_division=0)
                for a, b, c in zip(p, r, fscore):
                    metric_log.write('%.5f %.5f %.5f\n' % (a, b, c))
                p, r, fscore, _ = precision_recall_fscore_support(flat_test_label, pred, average='micro', zero_division=0)
                metric_log.write('PRE REC F1 micro\n')
                metric_log.write('%.5f %.5f %.5f\n' % (p, r, fscore))
                p, r, fscore, _ = precision_recall_fscore_support(flat_test_label, pred, average='macro', zero_division=0)
                metric_log.write('PRE REC F1 macro\n')
                metric_log.write('%.5f %.5f %.5f\n' % (p, r, fscore))

            with open(cm_path, 'wb') as cm_log:
                pickle.dump(confusion_matrix(flat_test_label, pred), cm_log)

            log.write('%.3f %.4f %.6f %.3f   %s\n' % (
                train_acc, train_loss, test_time, test_acc,
                time.asctime(time.localtime(time.time())),
            ))
            log.flush()

            if test_acc > best_test_acc:
                best_test_acc = test_acc
                state = {'model': model.state_dict(), 'optimizer': optimizer.state_dict()}
                torch.save(state, args.checkpoint)


if __name__ == '__main__':
    main()
