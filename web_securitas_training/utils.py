import torch
import time
import torch.nn.functional as F

def test_epoch(model, test_data):
    ''' Epoch operation in training phase'''
    model.eval()
    
    global_acc = [0 for _ in range(6)]
    class_num = [0 for _ in range(6)]

    for batch in test_data:
        # prepare data
        src_seq, gold, _ = batch
        src_seq, gold = src_seq.cuda(), gold.cuda()
        gold = gold.contiguous().view(-1)

        pred = model(src_seq)
        # 相等位置输出1，否则0
        pred = F.softmax(pred, dim=-1).max(1)[1]
        
        y_pred = pred.cpu().numpy()
        gt = gold.cpu().numpy()
        
        for idx in range(y_pred.shape[0]):
            class_num[gt[idx]] += 1
            if y_pred[idx] == gt[idx]:
                global_acc[y_pred[idx]] += 1
        
        #n_correct = pred.eq(gold)
        #acc = n_correct.sum().item() * 100 / n_correct.shape[0]
        
    acc = sum(global_acc) / sum(class_num)
    temp = [0 for _ in range(6)]
    for idx in range(6):
        temp[idx] = global_acc[idx] / class_num[idx]
    avg_acc = sum(temp) / 6

    return acc, avg_acc