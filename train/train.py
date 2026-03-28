import argparse
import time
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from pathlib import Path
from sklearn.model_selection import train_test_split
from torch.utils.data import Dataset, DataLoader

# ── Dataset ──────────────────────────────────────────────────────────────────

class TrafficDataset(Dataset):
    def __init__(self, data: np.ndarray, labels: np.ndarray):
        # data: (N, features, window_size)
        self.data   = torch.from_numpy(data).float().contiguous()
        self.labels = torch.tensor(labels, dtype=torch.long).contiguous()

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        return self.data[idx], self.labels[idx]

def get_dataloaders(parquet_path, batch_size=1024, window_size=128, test_split=0.2):
    print(f"Loading {parquet_path}...")
    df = pd.read_parquet(parquet_path)

    # Automatically identify features. Exclude non-numeric and identifying columns.
    exclude = {'label', 'timestamp', '_blk', '_fid'}
    feature_cols = [c for c in df.columns if c not in exclude]
    
    # Filter out columns that are constant (BatchNorm/GroupNorm killers)
    valid_cols = []
    for c in feature_cols:
        if df[c].nunique() > 1:
            valid_cols.append(c)
        else:
            print(f"  Dropping constant feature: {c}")
    
    feature_cols = valid_cols

    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna(subset=['label'] + feature_cols).reset_index(drop=True)

    # Remap labels to 0..N-1
    unique_labels = sorted(df['label'].unique())
    label_map     = {orig: i for i, orig in enumerate(unique_labels)}
    df['label']   = df['label'].map(label_map)
    num_classes   = len(unique_labels)
    print(f"Loaded {len(df):,} packets | {num_classes} classes | {len(feature_cols)} features")

    # Window per label
    windowed_data, windowed_labels = [], []
    for lbl, group in df.groupby('label'):
        feats = group[feature_cols].values.astype(np.float32)
        n     = len(feats) // window_size
        if n == 0:
            continue
        feats = feats[:n * window_size].reshape(n, window_size, len(feature_cols))
        # Transpose to (N, features, window_size) for Conv1d
        feats = feats.transpose(0, 2, 1)
        windowed_data.append(feats)
        windowed_labels.extend([lbl] * n)

    data_arr   = np.concatenate(windowed_data, axis=0)   # (N, F, W)
    labels_arr = np.array(windowed_labels)

    X_train, X_val, y_train, y_val = train_test_split(
        data_arr, labels_arr, test_size=test_split, random_state=42, stratify=labels_arr
    )

    # Per-feature Global Z-score
    # X_train is (N, channels, seq)
    # We want mean/std per channel across all N and all seq
    mean = X_train.mean(axis=(0, 2), keepdims=True)
    std  = X_train.std(axis=(0, 2),  keepdims=True) + 1e-8
    
    X_train = (X_train - mean) / std
    X_val   = (X_val   - mean) / std

    # Robust clipping
    X_train = np.clip(X_train, -10, 10)
    X_val   = np.clip(X_val,   -10, 10)

    train_loader = DataLoader(TrafficDataset(X_train, y_train), batch_size=batch_size,
                              shuffle=True,  num_workers=4, pin_memory=True)
    val_loader   = DataLoader(TrafficDataset(X_val,   y_val),   batch_size=batch_size,
                              shuffle=False, num_workers=4, pin_memory=True)
    return train_loader, val_loader, num_classes, len(feature_cols)

# ── Model ─────────────────────────────────────────────────────────────────────

class ResBlock1D(nn.Module):
    def __init__(self, channels):
        super().__init__()
        # Use GroupNorm(4, ...) for stability
        self.net = nn.Sequential(
            nn.Conv1d(channels, channels, 3, padding=1, bias=False),
            nn.GroupNorm(4, channels),
            nn.ReLU(),
            nn.Conv1d(channels, channels, 3, padding=1, bias=False),
            nn.GroupNorm(4, channels)
        )
        self.relu = nn.ReLU()

    def forward(self, x):
        return self.relu(x + self.net(x))

class TrafficResNet(nn.Module):
    def __init__(self, num_classes, in_channels):
        super().__init__()
        self.stem = nn.Sequential(
            nn.Conv1d(in_channels, 64, 7, padding=3, bias=False),
            nn.GroupNorm(4, 64),
            nn.ReLU(),
            nn.MaxPool1d(2)
        )
        self.layer1 = ResBlock1D(64)
        self.layer2 = nn.Sequential(
            nn.Conv1d(64, 128, 3, stride=2, padding=1, bias=False),
            nn.GroupNorm(8, 128),
            nn.ReLU(),
            ResBlock1D(128)
        )
        self.layer3 = nn.Sequential(
            nn.Conv1d(128, 256, 3, stride=2, padding=1, bias=False),
            nn.GroupNorm(8, 256),
            nn.ReLU(),
            ResBlock1D(256)
        )
        self.pool = nn.AdaptiveAvgPool1d(1)
        self.fc   = nn.Linear(256, num_classes)

    def forward(self, x):
        x = self.stem(x)
        x = self.layer1(x)
        x = self.layer2(x)
        x = self.layer3(x)
        x = self.pool(x).flatten(1)
        return self.fc(x)

# ── Training loop ─────────────────────────────────────────────────────────────

def train():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data",        type=str,   default="../data/dataset_output/dataset.parquet")
    parser.add_argument("--batch-size",  type=int,   default=256)
    parser.add_argument("--epochs",      type=int,   default=300*2)
    parser.add_argument("--window-size", type=int,   default=128)
    parser.add_argument("--lr",          type=float, default=3e-4)
    parser.add_argument("--patience",    type=int,   default=300)
    args = parser.parse_args()

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Device: {device}")

    train_loader, val_loader, num_classes, num_features = get_dataloaders(
        args.data, batch_size=args.batch_size, window_size=args.window_size
    )

    model     = TrafficResNet(num_classes=num_classes, in_channels=num_features).to(device)
    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=1e-2)
    scheduler = torch.optim.lr_scheduler.OneCycleLR(
        optimizer, max_lr=args.lr, steps_per_epoch=len(train_loader), epochs=args.epochs
    )

    best_acc, patience_counter = 0.0, 0
    Path("checkpoints").mkdir(exist_ok=True)

    for epoch in range(1, args.epochs + 1):
        model.train()
        train_loss = train_correct = train_total = 0
        t0 = time.time()

        for inputs, targets in train_loader:
            inputs, targets = inputs.to(device), targets.to(device)
            optimizer.zero_grad(set_to_none=True)
            
            outputs = model(inputs)
            loss    = criterion(outputs, targets)
            
            if torch.isnan(loss):
                print("NaN loss detected. Skipping batch.")
                continue
                
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()

            train_loss    += loss.item()
            train_correct += outputs.argmax(1).eq(targets).sum().item()
            train_total   += targets.size(0)

        model.eval()
        val_loss = val_correct = val_total = 0
        with torch.no_grad():
            for inputs, targets in val_loader:
                inputs, targets = inputs.to(device), targets.to(device)
                outputs  = model(inputs)
                val_loss += criterion(outputs, targets).item()
                val_correct += outputs.argmax(1).eq(targets).sum().item()
                val_total   += targets.size(0)

        train_acc = 100. * train_correct / (train_total + 1e-8)
        val_acc   = 100. * val_correct   / (val_total   + 1e-8)
        print(f"Epoch {epoch:03d}/{args.epochs} [{time.time()-t0:.1f}s] | "
              f"Train Loss: {train_loss/len(train_loader):.4f} Acc: {train_acc:.2f}% | "
              f"Val Loss: {val_loss/len(val_loader):.4f} Acc: {val_acc:.2f}%")

        if val_acc > best_acc:
            best_acc, patience_counter = val_acc, 0
            torch.save(model.state_dict(), "checkpoints/best_resnet.pt")
            print(f"  -> best: {best_acc:.2f}%")
        else:
            patience_counter += 1
            if patience_counter >= args.patience:
                print("Early stopping.")
                break

    print(f"Done. Best val acc: {best_acc:.2f}%")

if __name__ == "__main__":
    train()