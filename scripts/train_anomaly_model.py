"""Train and evaluate the Q-SHIELD Isolation Forest detector.

Input CSV must be produced from labelled PCAP feature windows and contain all
FEATURE_COLUMNS plus a `label` column. Only rows labelled `normal` are used to
fit Isolation Forest. Known attack rows are held out for evaluation and are
never silently treated as normal training data.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

import joblib

from qshield.monitor.anomaly import (
    FEATURE_COLUMNS,
    IsolationForestAnomalyDetector,
    evaluate_labelled_csv,
)

ROOT = Path(__file__).resolve().parents[1]
KNOWN_ATTACK_LABELS = {"port_scan", "syn_flood", "failed_login", "replay", "tamper", "attack"}


def load_labelled_rows(path: Path) -> tuple[list[dict[str, float]], int, int]:
    if not path.is_file():
        raise SystemExit(
            f"Dataset not found: {path}\n"
            "Collect labelled PCAP windows first; the schema CSV is not training data."
        )

    normal_rows: list[dict[str, float]] = []
    attack_count = 0
    unknown_count = 0
    required = set(FEATURE_COLUMNS) | {"label"}

    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
            missing = sorted(required - set(reader.fieldnames or []))
            raise SystemExit(f"Dataset is missing required columns: {', '.join(missing)}")

        for line_number, raw in enumerate(reader, start=2):
            label = (raw.get("label") or "").strip().lower()
            if label in {"", "unknown"}:
                unknown_count += 1
                continue
            values: dict[str, float] = {}
            for column in FEATURE_COLUMNS:
                try:
                    value = float(raw[column])
                except (TypeError, ValueError):
                    raise SystemExit(f"Invalid numeric value in {column} at CSV line {line_number}")
                if not __import__("math").isfinite(value) or value < 0:
                    raise SystemExit(f"Feature {column} must be finite and non-negative at line {line_number}")
                values[column] = value
            if label == "normal":
                normal_rows.append(values)
            else:
                # Labels are supplied by the operator. Any non-normal, non-unknown
                # label is counted as an attack example for binary evaluation.
                attack_count += 1

    if len(normal_rows) < 3:
        raise SystemExit(f"Need at least 3 labelled normal windows; found {len(normal_rows)}.")
    if attack_count < 1:
        raise SystemExit("Need at least 1 labelled attack window to evaluate the detector.")
    return normal_rows, attack_count, unknown_count


def main() -> None:
    parser = argparse.ArgumentParser(description="Train Q-SHIELD Isolation Forest")
    parser.add_argument("--input", type=Path, default=ROOT / "data" / "labelled_windows.csv")
    parser.add_argument("--output", type=Path, default=ROOT / "data" / "anomaly_model.joblib")
    parser.add_argument("--report", type=Path, default=ROOT / "data" / "anomaly_training_report.json")
    parser.add_argument("--contamination", type=float, default=0.05)
    args = parser.parse_args()

    if not 0.0 < args.contamination <= 0.5:
        parser.error("--contamination must be greater than 0 and at most 0.5")

    normal_rows, attack_count, unknown_count = load_labelled_rows(args.input)
    try:
        metrics: dict[str, Any] = evaluate_labelled_csv(
            args.input, contamination=args.contamination
        )
    except (ValueError, OSError) as exc:
        raise SystemExit(f"Evaluation could not be completed: {exc}")

    # Fit the deployable model on all operator-labelled normal windows only.
    model = IsolationForestAnomalyDetector(
        contamination=args.contamination, random_state=42
    ).fit(normal_rows)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, args.output)

    report = {
        "model": "IsolationForest",
        "feature_columns": list(FEATURE_COLUMNS),
        "training_normal_windows": len(normal_rows),
        "labelled_attack_windows": attack_count,
        "ignored_unknown_windows": unknown_count,
        "contamination": args.contamination,
        "evaluation": metrics,
        "warning": "Metrics depend on the supplied labelled dataset; this model is a triage aid, not proof of an attack.",
    }
    args.report.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"Model trained on {len(normal_rows)} normal windows.")
    print(f"Known attack windows available for evaluation: {attack_count}")
    print("Held-out evaluation:")
    print(f"  Precision: {metrics['precision']:.3f}")
    print(f"  Recall:    {metrics['recall']:.3f}")
    print(f"  F1-score:  {metrics['f1']:.3f}")
    print(f"Model saved:  {args.output}")
    print(f"Report saved: {args.report}")


if __name__ == "__main__":
    main()