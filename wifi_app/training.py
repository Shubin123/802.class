"""Grouped training and baseline utilities for field-capture datasets."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import torch
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import StratifiedGroupKFold
from torch.utils.data import DataLoader, TensorDataset

from .contract import FEATURE_COLUMNS, FEATURE_SCHEMA_VERSION
from .models import TCNConfig, build_tcn


@dataclass(frozen=True)
class FieldArrays:
    x: np.ndarray  # N, C, W
    y: np.ndarray  # N, integer class index
    labels: tuple[str, ...]
    groups: np.ndarray
    valid_frames: np.ndarray
    frame: pd.DataFrame
    window_size: int
    metadata: dict[str, Any]


def _feature_column(name: str) -> str:
    return f"feature__{name}"


def load_field_dataset(path: str | Path, *, group_column: str = "source_session_id") -> FieldArrays:
    """Load a field Parquet dataset, validating the shared schema contract."""
    data_path = Path(path)
    df = pd.read_parquet(data_path)
    needed = {"label", "valid_frames", "schema_version", group_column} | {_feature_column(name) for name in FEATURE_COLUMNS}
    missing = needed - set(df.columns)
    if missing:
        raise ValueError(f"field dataset is missing columns: {sorted(missing)}")
    schema_values = set(str(v) for v in df["schema_version"].dropna().unique())
    if schema_values != {FEATURE_SCHEMA_VERSION}:
        raise ValueError(f"expected schema {FEATURE_SCHEMA_VERSION}, found {sorted(schema_values)}")
    if df.empty:
        raise ValueError("field dataset has no samples")
    groups = df[group_column].fillna("").astype(str).to_numpy()
    if np.any(groups == ""):
        raise ValueError(f"group column {group_column!r} contains empty values")

    matrices: list[np.ndarray] = []
    expected_width: int | None = None
    for name in FEATURE_COLUMNS:
        rows = [np.asarray(value, dtype=np.float32) for value in df[_feature_column(name)]]
        widths = {len(row) for row in rows}
        if len(widths) != 1:
            raise ValueError(f"feature {name!r} has inconsistent window widths: {sorted(widths)}")
        width = widths.pop()
        if expected_width is None:
            expected_width = width
        elif width != expected_width:
            raise ValueError("feature columns do not share a window width")
        matrices.append(np.stack(rows, axis=0))
    assert expected_width is not None
    x = np.stack(matrices, axis=1)
    if not np.isfinite(x).all():
        raise ValueError("field dataset contains non-finite feature values")
    valid = df["valid_frames"].astype(int).to_numpy()
    if np.any(valid < 1) or np.any(valid > expected_width):
        raise ValueError("valid_frames is outside the feature-window bounds")
    labels = tuple(sorted(str(value) for value in df["label"].astype(str).unique()))
    label_index = {label: index for index, label in enumerate(labels)}
    y = df["label"].astype(str).map(label_index).to_numpy(dtype=np.int64)
    metadata_path = data_path.with_suffix(data_path.suffix + ".meta.json")
    metadata: dict[str, Any] = {}
    if metadata_path.exists():
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        if metadata.get("schema_version") != FEATURE_SCHEMA_VERSION:
            raise ValueError(f"dataset metadata schema does not match {FEATURE_SCHEMA_VERSION}")
        if int(metadata.get("window_size", expected_width)) != expected_width:
            raise ValueError("dataset metadata window_size does not match feature data")
    return FieldArrays(x, y, labels, groups, valid, df, expected_width, metadata)


def grouped_split_indices(
    arrays: FieldArrays,
    *,
    folds: int = 5,
    fold_index: int = 0,
    random_state: int = 42,
) -> tuple[np.ndarray, np.ndarray]:
    """Return a stratified group split and reject insufficient label groups.

    All overlapping windows retain their manifest ``source_session_id`` and
    therefore cannot land in both partitions.  Requiring at least two groups
    per label is intentional: otherwise a per-class validation claim is false.
    """
    if folds < 2:
        raise ValueError("folds must be at least 2")
    per_label_groups = [len(set(arrays.groups[arrays.y == index])) for index in range(len(arrays.labels))]
    if min(per_label_groups) < 2:
        details = {label: count for label, count in zip(arrays.labels, per_label_groups)}
        raise ValueError(f"each label needs at least 2 distinct groups for validation: {details}")
    n_splits = min(folds, min(per_label_groups))
    splitter = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=random_state)
    splits = list(splitter.split(arrays.x, arrays.y, arrays.groups))
    if not 0 <= fold_index < len(splits):
        raise ValueError(f"fold_index must be in 0..{len(splits) - 1}")
    train_idx, val_idx = splits[fold_index]
    overlap = set(arrays.groups[train_idx]) & set(arrays.groups[val_idx])
    if overlap:
        raise AssertionError(f"group leakage detected: {sorted(overlap)[:3]}")
    train_labels, val_labels = set(arrays.y[train_idx]), set(arrays.y[val_idx])
    if train_labels != set(range(len(arrays.labels))) or val_labels != set(range(len(arrays.labels))):
        raise ValueError("chosen grouped split does not cover every label in both partitions")
    return train_idx, val_idx


def fit_normalizer(x: np.ndarray, valid_frames: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Fit per-feature mean/std using only real frames from training windows."""
    if x.ndim != 3:
        raise ValueError("x must be [samples, features, frames]")
    mask = np.arange(x.shape[2])[None, :] < valid_frames[:, None]
    mean = np.empty(x.shape[1], dtype=np.float32)
    std = np.empty(x.shape[1], dtype=np.float32)
    for channel in range(x.shape[1]):
        values = x[:, channel, :][mask]
        mean[channel] = float(values.mean())
        std[channel] = float(values.std()) + 1e-6
    return mean, std


def normalize_windows(x: np.ndarray, valid_frames: np.ndarray, mean: np.ndarray, std: np.ndarray) -> np.ndarray:
    """Normalize valid frames and keep zero padding at neutral zero."""
    result = (x - mean[None, :, None]) / std[None, :, None]
    mask = np.arange(x.shape[2])[None, :] < valid_frames[:, None]
    result = np.where(mask[:, None, :], result, 0.0)
    return np.clip(result, -12.0, 12.0).astype(np.float32)


def aggregate_windows(x: np.ndarray, valid_frames: np.ndarray) -> np.ndarray:
    """Classical control features: mean/std/min/max for each frame feature."""
    pieces: list[np.ndarray] = []
    for index, count in enumerate(valid_frames):
        values = x[index, :, :count]
        pieces.append(np.concatenate((values.mean(axis=1), values.std(axis=1), values.min(axis=1), values.max(axis=1))))
    return np.stack(pieces).astype(np.float32)


def metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, float]:
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
    }


def train_logistic_baseline(
    arrays: FieldArrays,
    train_idx: np.ndarray,
    val_idx: np.ndarray,
    *,
    random_state: int = 42,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Fit the mandatory aggregate-feature control model on the grouped split."""
    features = aggregate_windows(arrays.x, arrays.valid_frames)
    classifier = LogisticRegression(
        max_iter=2_000,
        class_weight="balanced",
        random_state=random_state,
    )
    classifier.fit(features[train_idx], arrays.y[train_idx])
    prediction = classifier.predict(features[val_idx])
    bundle = {
        "kind": "field-logistic-baseline-v1",
        "schema_version": FEATURE_SCHEMA_VERSION,
        "feature_columns": list(FEATURE_COLUMNS),
        "window_size": arrays.window_size,
        "labels": list(arrays.labels),
        "classifier": classifier,
        "preprocessing": arrays.metadata.get("preprocessing", {}),
    }
    report = {
        "model": "logistic_aggregate_baseline",
        "validation": metrics(arrays.y[val_idx], prediction),
        "train_samples": int(len(train_idx)),
        "validation_samples": int(len(val_idx)),
    }
    return bundle, report


def train_tcn(
    arrays: FieldArrays,
    train_idx: np.ndarray,
    val_idx: np.ndarray,
    *,
    width: int = 48,
    blocks: int = 4,
    dropout: float = 0.10,
    epochs: int = 60,
    batch_size: int = 128,
    learning_rate: float = 3e-4,
    weight_decay: float = 1e-4,
    patience: int = 10,
    unknown_threshold: float = 0.60,
    device: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Fit an export-friendly compact TCN on a grouped real-capture split."""
    if not 0.0 <= unknown_threshold <= 1.0:
        raise ValueError("unknown_threshold must be between 0 and 1")
    if epochs < 1 or batch_size < 1:
        raise ValueError("epochs and batch_size must be positive")
    selected_device = torch.device(device or ("cuda" if torch.cuda.is_available() else "cpu"))
    mean, std = fit_normalizer(arrays.x[train_idx], arrays.valid_frames[train_idx])
    x_train = normalize_windows(arrays.x[train_idx], arrays.valid_frames[train_idx], mean, std)
    x_val = normalize_windows(arrays.x[val_idx], arrays.valid_frames[val_idx], mean, std)
    train_loader = DataLoader(
        TensorDataset(torch.from_numpy(x_train), torch.from_numpy(arrays.y[train_idx])),
        batch_size=batch_size,
        shuffle=True,
        num_workers=0,
        pin_memory=selected_device.type == "cuda",
    )
    config = TCNConfig(len(FEATURE_COLUMNS), len(arrays.labels), width=width, blocks=blocks, dropout=dropout)
    model = build_tcn(config).to(selected_device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate, weight_decay=weight_decay)
    criterion = torch.nn.CrossEntropyLoss()
    best_state: dict[str, torch.Tensor] | None = None
    best_f1, stalled, history = -1.0, 0, []
    for epoch in range(1, epochs + 1):
        model.train()
        running_loss = 0.0
        count = 0
        for inputs, targets in train_loader:
            inputs, targets = inputs.to(selected_device), targets.to(selected_device)
            optimizer.zero_grad(set_to_none=True)
            loss = criterion(model(inputs), targets)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            running_loss += float(loss.item()) * len(targets)
            count += len(targets)
        model.eval()
        with torch.no_grad():
            logits = model(torch.from_numpy(x_val).to(selected_device))
            pred = logits.argmax(dim=1).cpu().numpy()
        value = metrics(arrays.y[val_idx], pred)
        value["epoch"] = epoch
        value["train_loss"] = running_loss / max(1, count)
        history.append(value)
        if value["macro_f1"] > best_f1:
            best_f1 = value["macro_f1"]
            best_state = copy.deepcopy(model.state_dict())
            stalled = 0
        else:
            stalled += 1
            if stalled >= patience:
                break
    assert best_state is not None
    model.load_state_dict(best_state)
    model.eval()
    with torch.no_grad():
        logits = model(torch.from_numpy(x_val).to(selected_device))
        probabilities = torch.softmax(logits, dim=1).cpu().numpy()
        prediction = probabilities.argmax(axis=1)
    confidence = probabilities.max(axis=1)
    accepted = confidence >= unknown_threshold
    known = metrics(arrays.y[val_idx], prediction)
    known["coverage_at_threshold"] = float(accepted.mean())
    # This validates the abstention mechanism only on known classes. Actual
    # unknown false-accept needs a deliberately held-out unknown corpus.
    known["known_rejection_rate_at_threshold"] = float((~accepted).mean())
    bundle = {
        "kind": "field-tcn-v1",
        "schema_version": FEATURE_SCHEMA_VERSION,
        "feature_columns": list(FEATURE_COLUMNS),
        "window_size": arrays.window_size,
        "labels": list(arrays.labels),
        "model_config": {
            "in_channels": config.in_channels,
            "num_classes": config.num_classes,
            "width": config.width,
            "blocks": config.blocks,
            "dropout": config.dropout,
        },
        "state_dict": {key: value.detach().cpu() for key, value in model.state_dict().items()},
        "normalizer": {"mean": mean, "std": std},
        "unknown_threshold": float(unknown_threshold),
        "preprocessing": arrays.metadata.get("preprocessing", {}),
    }
    report = {
        "model": "compact_tcn",
        "device": str(selected_device),
        "train_samples": int(len(train_idx)),
        "validation_samples": int(len(val_idx)),
        "validation": known,
        "best_macro_f1": float(best_f1),
        "epochs_ran": len(history),
        "history": history,
        "note": "unknown threshold is provisional until calibrated with held-out unknown capture domains",
    }
    return bundle, report


def save_bundle(bundle: dict[str, Any], report: dict[str, Any], out_path: str | Path) -> tuple[Path, Path]:
    """Save a model bundle and adjacent JSON report without mixing legacy formats."""
    output = Path(out_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    if bundle["kind"] == "field-logistic-baseline-v1":
        joblib.dump(bundle, output)
    else:
        torch.save(bundle, output)
    report_path = output.with_suffix(output.suffix + ".report.json")
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return output, report_path


def export_tcn_onnx(bundle: dict[str, Any], out_path: str | Path) -> Path:
    """Export a static-window TCN checkpoint to ONNX and verify it can be loaded."""
    if bundle.get("kind") != "field-tcn-v1":
        raise ValueError("only field-tcn-v1 checkpoints can be exported to ONNX")
    model = build_tcn(bundle["model_config"])
    model.load_state_dict(bundle["state_dict"])
    model.eval()
    output = Path(out_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    dummy = torch.zeros((1, len(FEATURE_COLUMNS), int(bundle["window_size"])), dtype=torch.float32)
    torch.onnx.export(
        model,
        dummy,
        str(output),
        input_names=["features"],
        output_names=["logits"],
        opset_version=17,
        dynamo=False,
    )
    try:
        import onnx
        onnx.checker.check_model(str(output))
    except ImportError:  # pragma: no cover - optional verification dependency
        pass
    return output
