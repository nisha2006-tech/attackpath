import csv

import numpy as np
from sklearn.linear_model import LogisticRegression

from attackpath.features import TARGETS, COLUMNS
from attackpath.ingest import parse_nmap_xml
from attackpath.graph import build_graph
from attackpath.evaluate import our_ranking, precision_at_k, average_precision

FEATURES = [c for c in COLUMNS if c not in ("target", "port", "name", "label")]


def load_rows(path="data/features.csv"):
    with open(path) as f:
        return list(csv.DictReader(f))


def to_x(rows):
    return np.array([[float(r[f]) / (10.0 if f == "max_cvss" else 1.0) for f in FEATURES]
                     for r in rows])


def to_y(rows):
    return np.array([int(r["label"]) for r in rows])


def make_model():
    return LogisticRegression(class_weight="balanced", max_iter=1000)


def main():
    rows = load_rows()
    print(f"{'Held-out':<10}{'Method':<14}{'P@5':>6}{'AP':>8}")
    totals = {"ML": [], "AttackPath": []}

    for name, scan, _ in TARGETS:
        train = [r for r in rows if r["target"] != name]
        test = [r for r in rows if r["target"] == name]

        model = make_model().fit(to_x(train), to_y(train))
        probs = model.predict_proba(to_x(test))[:, 1]
        ports = [int(r["port"]) for r in test]
        ml_rank = [p for _, p in sorted(zip(probs, ports), key=lambda x: (-x[0], x[1]))]

        truth = {int(r["port"]) for r in test if r["label"] == "1"}
        hand_rank = our_ranking(build_graph(parse_nmap_xml(scan)))

        for label, ranked in (("ML", ml_rank), ("AttackPath", hand_rank)):
            p5 = precision_at_k(ranked, truth, 5)
            ap = average_precision(ranked, truth)
            totals[label].append((p5, ap))
            print(f"{name:<10}{label:<14}{p5:>6.2f}{ap:>8.3f}")

    print("\nMean over the 3 held-out targets")
    for label, vals in totals.items():
        print(f"{label:<14} P@5={np.mean([v[0] for v in vals]):.2f}  "
              f"AP={np.mean([v[1] for v in vals]):.3f}")

    full = make_model().fit(to_x(rows), to_y(rows))
    print("\nLearned weights (trained on all data, for interpretation only)")
    for feat, w in sorted(zip(FEATURES, full.coef_[0]), key=lambda x: -abs(x[1])):
        print(f"  {feat:<22}{w:>7.2f}")


if __name__ == "__main__":
    main()
