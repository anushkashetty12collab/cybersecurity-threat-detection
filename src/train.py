"""
Task 1 - Step 3: Train + evaluate models.

* Time-based split (first 70% of time = train, last 30% = test) -> no leakage from the future.
* Models: Logistic Regression (baseline), Random Forest, Gradient Boosting, Isolation Forest (unsupervised).
* Metrics: precision, recall, F1, PR-AUC, confusion matrix.
* Outputs: models/model.joblib, models/metrics.json, reports/*.png, reports/false_positives.csv

Run: python -m src.train
"""
import json
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, confusion_matrix, f1_score,
                             precision_recall_curve, precision_score, recall_score)
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from src.preprocess import FEATURES

SEED = 42


def evaluate(name, y_true, y_pred, y_score):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    return {
        "model": name,
        "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_true, y_pred), 4),
        "f1": round(f1_score(y_true, y_pred), 4),
        "pr_auc": round(average_precision_score(y_true, y_score), 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "false_positive_rate": round(fp / (fp + tn), 5),
    }


def main():
    df = pd.read_csv("data/processed/features.csv", parse_dates=["timestamp"]).sort_values("timestamp")
    split_ts = df["timestamp"].quantile(0.70)
    train, test = df[df.timestamp <= split_ts], df[df.timestamp > split_ts].copy()
    Xtr, ytr = train[FEATURES], train["is_suspicious"]
    Xte, yte = test[FEATURES], test["is_suspicious"]
    print(f"Train: {len(train):,} rows ({ytr.mean():.1%} suspicious) | "
          f"Test: {len(test):,} rows ({yte.mean():.1%} suspicious)\n")

    models = {
        "LogisticRegression": make_pipeline(StandardScaler(),
                                            LogisticRegression(class_weight="balanced", max_iter=2000)),
        "RandomForest": RandomForestClassifier(n_estimators=300, class_weight="balanced_subsample",
                                               min_samples_leaf=2, n_jobs=-1, random_state=SEED),
        "GradientBoosting": GradientBoostingClassifier(random_state=SEED),
    }
    results, scores = [], {}
    for name, m in models.items():
        m.fit(Xtr, ytr)
        proba = m.predict_proba(Xte)[:, 1]
        scores[name] = proba
        results.append(evaluate(name, yte, (proba >= 0.5).astype(int), proba))

    # Unsupervised comparison: trained on train features only, no labels
    iso = IsolationForest(n_estimators=300, contamination=float(ytr.mean()), random_state=SEED)
    iso.fit(Xtr)
    iso_score = -iso.score_samples(Xte)
    iso_pred = (iso.predict(Xte) == -1).astype(int)
    results.append(evaluate("IsolationForest (unsupervised)", yte, iso_pred, iso_score))

    print(pd.DataFrame(results).drop(columns="confusion_matrix").to_string(index=False))

    # ---- choose best supervised model by PR-AUC, then F1
    supervised = [r for r in results if "unsupervised" not in r["model"]]
    best = max(supervised, key=lambda r: (r["pr_auc"], r["f1"]))["model"]
    print(f"\nBest model: {best}")
    best_model = models[best]

    # ---- save artefacts
    Path("models").mkdir(exist_ok=True)
    Path("reports").mkdir(exist_ok=True)
    joblib.dump({"model": best_model, "features": FEATURES, "threshold": 0.5}, "models/model.joblib")
    with open("models/metrics.json", "w") as f:
        json.dump({"best_model": best, "split_timestamp": str(split_ts), "results": results}, f, indent=2)

    # ---- false positives / false negatives for the report
    test["score"] = scores[best]
    test["pred"] = (test["score"] >= 0.5).astype(int)
    cols = ["event_id", "timestamp", "source_ip", "dest_ip", "user", "event_type", "status",
            "port", "bytes_out", "attack_type", "score"]
    test[(test.pred == 1) & (test.is_suspicious == 0)][cols].to_csv("reports/false_positives.csv", index=False)
    test[(test.pred == 0) & (test.is_suspicious == 1)][cols].to_csv("reports/false_negatives.csv", index=False)
    print("\nFalse positives by source:")
    fp = test[(test.pred == 1) & (test.is_suspicious == 0)]
    print(fp.groupby(["source_ip", "event_type"]).size().sort_values(ascending=False).head(8).to_string())

    # per-attack-type recall
    print("\nRecall per attack type (best model):")
    att = test[test.is_suspicious == 1].groupby("attack_type")["pred"].agg(["mean", "count"])
    print(att.rename(columns={"mean": "recall", "count": "n_events"}).round(3).to_string())

    # ---- plots
    plt.figure(figsize=(6, 4.5))
    for name, s in scores.items():
        p, r, _ = precision_recall_curve(yte, s)
        plt.plot(r, p, label=name)
    plt.xlabel("Recall"); plt.ylabel("Precision"); plt.title("Precision-Recall (time-based test set)")
    plt.legend(); plt.tight_layout(); plt.savefig("reports/pr_curve.png", dpi=150); plt.close()

    if hasattr(best_model, "feature_importances_"):
        imp = pd.Series(best_model.feature_importances_, index=FEATURES).sort_values()
        imp.to_csv("models/feature_importances.csv", header=["importance"])
        plt.figure(figsize=(6, 6)); imp.tail(15).plot.barh()
        plt.title(f"Top features - {best}"); plt.tight_layout()
        plt.savefig("reports/feature_importance.png", dpi=150); plt.close()
        print("\nTop 8 features:\n", imp.sort_values(ascending=False).head(8).round(3).to_string())


if __name__ == "__main__":
    main()