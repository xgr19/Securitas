import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
from torch.distributions.categorical import Categorical
from torch.utils.data import TensorDataset, DataLoader
from tqdm import trange
import time
import random
import copy

# global variables
eps = np.finfo(np.float32).eps.item()
embedding_size = 32

global_number_choice = [0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88]
icmp_pkt_size = 28
icmp_prob = 0.48

class robot():
    class p_pi(nn.Module):
        #policy network
        def __init__(self, space):
            super().__init__()
            input_space = copy.deepcopy(space)
            input_space[0] = 10
            self.embedding_list = nn.ModuleList([nn.Embedding(input_space[i], embedding_size) for i in range(len(input_space))])
            self.lstm = nn.LSTM(embedding_size, embedding_size, batch_first=True)
            self.linear_list = nn.ModuleList([nn.Linear(embedding_size, space[i]) for i in range(len(space))])
            self.stage = 0
            self.hidden = None

        def forward(self, x):
            x = self.embedding_list[self.stage](x)
            self.lstm.flatten_parameters()
            x, self.hidden = self.lstm(x, self.hidden)
            prob = self.linear_list[self.stage](x.view(x.size(0), -1))
            return prob

        def increment_stage(self):
            self.stage += 1
        def reset(self):
            self.stage = 0
            self.hidden = None

    def __init__(self, space, rl_batch, lr):
        self.mind = self.p_pi(space)
        self.optimizer = optim.Adam(self.mind.parameters(), lr=lr)
        self.combo_size = len(space)
        self.rl_batch = rl_batch

    def select_action(self, state, mode):
        p_a = F.softmax(self.mind(state), dim=1)
        if mode == 'train':
            dist = Categorical(probs=p_a)
            action = dist.sample()
            log_p_action = dist.log_prob(action)
            return action.unsqueeze(-1), log_p_action.unsqueeze(-1)
        elif mode == 'test':
            res = torch.argmax(p_a, dim=1)
            return res.unsqueeze(-1), res.unsqueeze(-1)

    def select_combo(self, mode):
        state = torch.from_numpy(np.random.randint(0, 8, size=(self.rl_batch, 1))).long().cuda()
        combo = []
        log_p_combo = []
        for _ in range(self.combo_size):
            action, log_p_action = self.select_action(state, mode=mode)
            combo.append(action)
            log_p_combo.append(log_p_action)
            state = action
            self.mind.increment_stage()
        combo = torch.cat(combo, dim=1)
        log_p_combo = torch.cat(log_p_combo, dim=1)
        return combo, log_p_combo


class agent(robot):
    ### MODIFIED ###
    def __init__(self, model, training_data, test_data, patch_length, loss_weights, split_ratio):
        self.model = model
        self.training_data = training_data
        self.test_data = test_data
        self.patch_length = patch_length
        self.space = [len(global_number_choice) for _ in range(self.patch_length)]
        self.loss_weights = loss_weights
        self.split_ratio = split_ratio

    def build_robot(self, rl_batch, lr):
        super().__init__(self.space, rl_batch, lr)
    
    ### MODIFIED ###
    # This function now implements the random choice and returns bandwidth info for the loss function
    def apply_patch(self, combo, clip_batch, direction):
        combo = combo[0:clip_batch.shape[0],:].cpu().numpy()
        clip_batch_np = clip_batch.cpu().numpy()
        direction_np = direction.cpu().numpy()
        new_batch_tensor = np.zeros_like(clip_batch_np)
        
        batch_flow_size = np.sum(clip_batch_np)
        batch_overhead = 0
        
        for dim_1 in range(clip_batch_np.shape[0]):
            dim_2 = 0
            idx = 0
            operation = 0
            icmp_pool = []
            point_neg = 0
            while point_neg < clip_batch_np.shape[1] and direction_np[dim_1][point_neg] == -1:
                point_neg += 1
            
            while idx < self.patch_length:
                if dim_2 == clip_batch_np.shape[1]: break
                if direction_np[dim_1][dim_2 - operation] == 0: break
                
                if dim_2 - operation in icmp_pool:
                    icmp_pool.remove(dim_2 - operation)
                    new_batch_tensor[dim_1][dim_2] = icmp_pkt_size
                    batch_overhead += (icmp_pkt_size + 20 + 14)
                    dim_2 += 1
                    operation += 1
                    continue
                if direction_np[dim_1][dim_2 - operation] == 1:
                    new_batch_tensor[dim_1][dim_2] = clip_batch_np[dim_1][dim_2 - operation]
                    dim_2 += 1
                    if point_neg < clip_batch_np.shape[1]:
                        point_neg += 1
                        while point_neg < clip_batch_np.shape[1] and direction_np[dim_1][point_neg] == -1: point_neg += 1
                    continue

                now_choice = combo[dim_1][idx]
                idx += 1
                
                if now_choice == 0:
                    new_batch_tensor[dim_1][dim_2] = clip_batch_np[dim_1][dim_2 - operation]
                    dim_2 += 1
                else: 
                    operation += 1
                    # --- NEW: Randomly choose between dummy and split ---
                    if random.random() < self.split_ratio:
                        # --- Perform SPLIT logic ---
                        split = global_number_choice[now_choice]
                        if clip_batch_np[dim_1][dim_2 - operation + 1] <= split: # split fail, dummy
                            new_batch_tensor[dim_1][dim_2] = clip_batch_np[dim_1][dim_2 - operation + 1]
                            dim_2 += 1; 
                            if dim_2 == clip_batch_np.shape[1]: break
                            new_batch_tensor[dim_1][dim_2] = split
                            batch_overhead += (split + 20 + 14)
                            dim_2 += 1
                        else: # split success
                            new_batch_tensor[dim_1][dim_2] = clip_batch_np[dim_1][dim_2 - operation + 1] - split
                            dim_2 += 1
                            if dim_2 == clip_batch_np.shape[1]: break
                            new_batch_tensor[dim_1][dim_2] = split
                            batch_overhead += (20 + 14)
                            dim_2 += 1
                    else:
                        # --- Perform DUMMY PACKET logic ---
                        dummy_size = global_number_choice[now_choice]
                        new_batch_tensor[dim_1][dim_2] = clip_batch_np[dim_1][dim_2 - operation + 1]
                        dim_2 += 1
                        if dim_2 == clip_batch_np.shape[1]: break
                        new_batch_tensor[dim_1][dim_2] = dummy_size
                        batch_overhead += (dummy_size + 20 + 14)
                        dim_2 += 1

                    if dim_2 - operation > point_neg: exit(0)
                    icmp_pos = random.randint(dim_2 - operation, point_neg)
                    if random.random() < icmp_prob: icmp_pool.append(icmp_pos)
            
            start = dim_2 - operation
            while dim_2 < clip_batch_np.shape[1]:
                new_batch_tensor[dim_1][dim_2] = clip_batch_np[dim_1][start]
                dim_2 += 1
                start += 1
        
        new_batch_tensor = torch.from_numpy(new_batch_tensor).long().cuda()
        return new_batch_tensor, batch_flow_size, batch_overhead
    
    ### NEW ###
    # This is the new reinforcement learn function using the composite loss.
    def reinforcement_learn(self, steps, f):
        self.mind.cuda()
        self.mind.train()
        
        for tensor in self.training_data:
            self.optimizer.zero_grad()
            clip_tensor, target_tensor, train_direction = tensor
            clip_tensor, target_tensor, train_direction = clip_tensor.cuda(), target_tensor.cuda(), train_direction.cuda()
            clip_batch = clip_tensor
            target_batch = target_tensor.view(target_tensor.shape[0], 1)
            
            for _ in range(steps):
                combo, log_p_combo = self.select_combo(mode='train')
                
                new_clip_batch, flow_size, overhead = self.apply_patch(combo, clip_batch, train_direction)
                
                # --- NEW COMPOSITE LOSS CALCULATION ---
                # 1. Accuracy Loss
                output_tensor = self.model(new_clip_batch)
                output_softmax = F.softmax(output_tensor, dim=1)
                p_correct = torch.gather(output_softmax, dim=1, index=target_batch)
                loss_accuracy = p_correct.mean()

                # 2. Bandwidth Loss
                loss_bandwidth = (flow_size + overhead) / (flow_size + eps)
                loss_bandwidth = torch.tensor(loss_bandwidth, device='cuda').float()

                # 3. Transferability/Similarity Loss
                l2_dist = torch.norm(new_clip_batch.float() - clip_batch.float(), p=2, dim=-1)
                norm_factor = torch.norm(clip_batch.float(), p=2, dim=-1)
                loss_similarity = (l2_dist / (norm_factor + eps)).mean()
                
                w_acc, w_trans, w_bw = self.loss_weights
                total_loss_value = w_acc * loss_accuracy - w_trans * loss_similarity + w_bw * loss_bandwidth

                policy_loss = (log_p_combo.sum(dim=1) * total_loss_value.detach()).mean()
                
                policy_loss.backward(retain_graph=True)
                self.optimizer.step()
                self.optimizer.zero_grad()
                self.mind.reset()
    
    ### MODIFIED ###
    # test_acc is reverted to its simpler form without bandwidth calculation
    def test_acc(self, model, test_data):
        self.mind.cuda()
        self.mind.eval()
        
        num_classes = 6
        global_acc = [0 for _ in range(num_classes)]
        class_num = [0 for _ in range(num_classes)]
        
        for batch in test_data:
            clip_batch, target_batch, test_direction = batch
            clip_batch, target_batch, test_direction = clip_batch.cuda(), target_batch.cuda(), test_direction.cuda()
            
            combo, _ = self.select_combo(mode='test')
            self.mind.reset()

            # The apply_patch returns 3 values; we only need the first for testing accuracy
            new_clip_batch, _, _ = self.apply_patch(combo, clip_batch, test_direction)
            
            pred = model(new_clip_batch)
            pred = F.softmax(pred, dim=-1).max(1)[1]
            
            y_pred = pred.cpu().numpy()
            gt = target_batch.cpu().numpy()
            
            for idx in range(y_pred.shape[0]):
                class_num[gt[idx]] += 1
                if y_pred[idx] == gt[idx]:
                    global_acc[y_pred[idx]] += 1
        
        acc = sum(global_acc) / (sum(class_num) + eps)
        
        temp = [0 for _ in range(num_classes)]
        num_valid_classes = 0
        for idx in range(num_classes):
            if class_num[idx] > 0:
                temp[idx] = global_acc[idx] / class_num[idx]
                num_valid_classes += 1
        
        avg_acc = sum(temp) / (num_valid_classes + eps)
            
        return acc, avg_acc

    @staticmethod
    def attack(model, training_data, test_data, lr, rl_batch, steps, epochs, f, patch_len, model_save_dir,
               loss_weights=None, split_ratio=0.7):
        test_best_acc = 100
        avg_best_acc = 0
        
        if loss_weights is None:
            loss_weights = [0.6, 0.2, 0.2]
        
        actor = agent(model, training_data, test_data, patch_len, loss_weights, split_ratio)
        actor.build_robot(rl_batch=rl_batch, lr=lr)
        for now_epoch in trange(epochs, mininterval=1, desc='  - (Training)   ', leave=False):
            f.write('now_epoch = %d    %s\n' % (now_epoch + 1, time.asctime(time.localtime(time.time()))))
            actor.reinforcement_learn(steps=steps, f=f)
            
            ### MODIFIED ###
            # Reverted to calling the simpler test_acc
            acc, avg_acc = actor.test_acc(model=model, test_data=test_data)
            
            if acc < test_best_acc:
                test_best_acc = acc
                avg_best_acc = avg_acc
                torch.save(actor.mind.state_dict(), model_save_dir + 'best_mind.pth')
            
            # Reverted to the simpler log output
            f.write('test_acc = %.3f, avg_acc = %.3f, test_best_acc = %.3f, avg_best_acc = %.3f\n' % 
                    (acc * 100, avg_acc * 100, test_best_acc * 100, avg_best_acc * 100))
            f.flush()
            
        return actor
