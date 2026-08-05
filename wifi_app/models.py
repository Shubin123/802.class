"""Small, export-friendly temporal models for capture-native metadata windows."""

from __future__ import annotations

from dataclasses import asdict, dataclass

import torch
import torch.nn as nn


@dataclass(frozen=True)
class TCNConfig:
    in_channels: int
    num_classes: int
    width: int = 48
    blocks: int = 4
    dropout: float = 0.10


class TemporalBlock(nn.Module):
    """Two dilated Conv1D layers using only broadly exportable operators."""

    def __init__(self, channels: int, dilation: int, dropout: float) -> None:
        super().__init__()
        self.conv1 = nn.Conv1d(channels, channels, kernel_size=3, padding=dilation, dilation=dilation)
        self.relu1 = nn.ReLU(inplace=True)
        self.dropout = nn.Dropout(dropout)
        self.conv2 = nn.Conv1d(channels, channels, kernel_size=3, padding=dilation, dilation=dilation)
        self.relu2 = nn.ReLU(inplace=True)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        residual = x
        x = self.conv1(x)
        x = self.relu1(x)
        x = self.dropout(x)
        x = self.conv2(x)
        return self.relu2(x + residual)


class CompactTCN(nn.Module):
    """Static-window TCN suitable for ONNX Runtime Web / WebGPU evaluation."""

    def __init__(self, config: TCNConfig) -> None:
        super().__init__()
        self.config = config
        self.stem = nn.Sequential(
            nn.Conv1d(config.in_channels, config.width, kernel_size=1),
            nn.ReLU(inplace=True),
        )
        self.blocks = nn.Sequential(*[
            TemporalBlock(config.width, dilation=2 ** index, dropout=config.dropout)
            for index in range(config.blocks)
        ])
        self.pool = nn.AdaptiveAvgPool1d(1)
        self.classifier = nn.Linear(config.width, config.num_classes)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.stem(x)
        x = self.blocks(x)
        x = self.pool(x).squeeze(-1)
        return self.classifier(x)


def model_config_dict(model: CompactTCN) -> dict[str, object]:
    return asdict(model.config)


def build_tcn(config: dict[str, object] | TCNConfig) -> CompactTCN:
    if isinstance(config, dict):
        config = TCNConfig(**config)
    return CompactTCN(config)
