import torch
import torch.nn as nn


class APPNet(nn.Module):
    def __init__(self, num_classes=6):
        super().__init__()
        self.embedding = nn.Embedding(num_embeddings=1600, embedding_dim=128)

        self.lstm1 = nn.LSTM(128, 128, batch_first=True, bidirectional=True)
        self.lstm2 = nn.LSTM(256, 128, batch_first=True, bidirectional=True)

        self.conv1 = nn.Sequential(
            nn.Conv1d(in_channels=128, out_channels=256, kernel_size=5, stride=1, padding=2),
            nn.MaxPool1d(kernel_size=3, stride=1, padding=1),
            nn.BatchNorm1d(256),
        )
        self.conv2 = nn.Sequential(
            nn.Conv1d(in_channels=256, out_channels=256, kernel_size=5, stride=1, padding=2),
            nn.MaxPool1d(kernel_size=3, stride=1, padding=1),
            nn.BatchNorm1d(256),
        )

        self.pooling = nn.AdaptiveAvgPool1d(1)
        self.fc = nn.Linear(in_features=256, out_features=num_classes)

    def forward(self, x):
        h = self.embedding(x)

        h1, _ = self.lstm1(h)
        h1, _ = self.lstm2(h1)
        h1 = h1.transpose(-2, -1)
        h1 = self.pooling(h1).view(h1.size(0), -1)

        h2 = h.transpose(-2, -1)
        h2 = self.conv1(h2)
        h2 = self.conv2(h2)
        h2 = self.pooling(h2).view(h2.size(0), -1)

        return self.fc(h1 + h2)


APP_net = APPNet
