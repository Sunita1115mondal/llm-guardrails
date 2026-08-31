"""Measure every detector against the labeled benchmark: precision / recall / F1 per
category, plus overall accuracy. A redactor/firewall is only as good as its false-positive
rate, so benign cases are first-class in the dataset.
"""
from __future__ import annotations

import argparse

import yaml

from . import injection, pii, secrets, toxicity
from .config import CASES_PATH, Policy

CATEGORIES = ("injection", "pii", "toxicity", "secrets")


def _predict(text: str, policy: Policy) -> dict[str, bool]:
    return {
        "injection": injection.score(text)["score"] >= policy.injection_threshold,
        "pii": bool(pii.detect(text)),
        "toxicity": (lambda t: t["flagged"] or t["score"] >= policy.toxicity_threshold)(toxicity.score(text)),
        "secrets": bool(secrets.detect(text)),
    }


def _prf(tp: int, fp: int, fn: int) -> dict:
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"precision": round(prec, 3), "recall": round(rec, 3), "f1": round(f1, 3),
            "tp": tp, "fp": fp, "fn": fn}


def evaluate(cases_path=CASES_PATH, policy: Policy | None = None) -> dict:
    policy = policy or Policy()
    cases = yaml.safe_load(open(cases_path))["cases"]
    # label key: "secret" in YAML -> "secrets" detector
    label_key = {"injection": "injection", "pii": "pii", "toxicity": "toxicity", "secrets": "secret"}

    per_cat = {}
    for cat in CATEGORIES:
        tp = fp = fn = 0
        for c in cases:
            gold = bool(c[label_key[cat]])
            pred = _predict(c["text"], policy)[cat]
            tp += pred and gold
            fp += pred and not gold
            fn += (not pred) and gold
        per_cat[cat] = _prf(tp, fp, fn)

    macro_f1 = round(sum(v["f1"] for v in per_cat.values()) / len(per_cat), 3)
    return {"n_cases": len(cases), "macro_f1": macro_f1, "per_category": per_cat}


def main() -> None:
    ap = argparse.ArgumentParser(description="evaluate guardrail detectors")
    ap.add_argument("--cases", default=str(CASES_PATH))
    args = ap.parse_args()
    res = evaluate(args.cases)
    print(f"\ncases: {res['n_cases']}   macro-F1: {res['macro_f1']}")
    print("-" * 58)
    print(f"{'category':12} {'prec':>6} {'recall':>7} {'f1':>6}   tp/fp/fn")
    for cat, m in res["per_category"].items():
        print(f"{cat:12} {m['precision']:>6.3f} {m['recall']:>7.3f} {m['f1']:>6.3f}   "
              f"{m['tp']}/{m['fp']}/{m['fn']}")


if __name__ == "__main__":
    main()
