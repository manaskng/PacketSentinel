#!/usr/bin/env python3
"""
train_anomaly_model.py — Offline ML training pipeline for PacketSentinel anomaly detection.

Reads per-flow feature vectors exported by the C++ engine (--export-features flag),
trains a Random Forest classifier, and reports accuracy metrics.

Feature vector columns (from flow_features.csv):
  src_ip, dst_ip, src_port, dst_port, protocol,
  packet_count, byte_count, avg_pkt_size, pkt_size_variance,
  payload_entropy, syn_count, fin_count, rst_count,
  duration_ms, anomaly_score, anomaly_type

Feature choices are aligned with NSL-KDD and CICIDS2017 research datasets:
  - NSL-KDD:    duration, protocol, src_bytes, dst_bytes, land, wrong_fragment,
                flag counts (SYN, FIN, REJ)
  - CICIDS2017: Flow Duration, Total Fwd Packets, Fwd Packet Length Mean,
                Bwd Packet Length Std, Flow Bytes/s, Packet Length Variance,
                Packet Length Std, SYN Flag Count, RST Flag Count

Usage:
  # First, run the C++ engine with --export-features:
  # ./dpi_engine input.pcap output.pcap --anomaly --export-features flow_features.csv --stats-json

  python scripts/train_anomaly_model.py
  python scripts/train_anomaly_model.py --features flow_features.csv --output model_report.txt
"""

import sys
import os
import argparse

def check_dependencies():
    """Check if scikit-learn and pandas are available."""
    missing = []
    try:
        import pandas
    except ImportError:
        missing.append("pandas")
    try:
        import sklearn
    except ImportError:
        missing.append("scikit-learn")
    try:
        import numpy
    except ImportError:
        missing.append("numpy")

    if missing:
        print("ERROR: Missing required Python packages:", ", ".join(missing))
        print("\nInstall them with:")
        print(f"  pip install {' '.join(missing)}")
        print("\nOr with uv:")
        print(f"  uv pip install {' '.join(missing)}")
        sys.exit(1)

def generate_synthetic_features(n_normal=2000, n_attack=500):
    """
    Generate synthetic flow features for demonstration when no CSV is available.
    Mirrors the feature distribution of the PCAP generator's attack traffic.
    """
    import numpy as np
    import pandas as pd

    rng = np.random.default_rng(42)

    # Normal traffic: varied sizes, low entropy variance, balanced flags
    # We inject some noise: normal flows with high entropy (like TLS) and low variance
    normal = {
        'packet_count':      rng.integers(1, 50,    n_normal),
        'byte_count':        rng.integers(40, 8000, n_normal),
        'avg_pkt_size':      rng.uniform(40, 600,    n_normal),
        'pkt_size_variance': rng.uniform(0, 5000,  n_normal), # Noise: overlaps with DDoS
        'payload_entropy':   rng.uniform(3.5, 7.8,   n_normal), # Noise: overlaps with Exfil
        'syn_count':         rng.integers(1, 4,       n_normal),
        'fin_count':         rng.integers(0, 3,       n_normal),
        'rst_count':         rng.integers(0, 2,       n_normal),
        'duration_ms':       rng.uniform(10, 5000,    n_normal),
        'label':             ['NORMAL'] * n_normal,
    }

    # Port scan: 1-5 packets, mostly SYN
    n_scan = n_attack // 3
    scan = {
        'packet_count':      rng.integers(1, 5,       n_scan),
        'byte_count':        rng.integers(40, 200,    n_scan),
        'avg_pkt_size':      rng.uniform(40, 80,      n_scan),
        'pkt_size_variance': rng.uniform(0, 50,       n_scan),
        'payload_entropy':   rng.uniform(0.0, 3.5,    n_scan),
        'syn_count':         rng.integers(1, 3,       n_scan),
        'fin_count':         rng.integers(0, 2,       n_scan), # Noise
        'rst_count':         rng.integers(0, 2,       n_scan),
        'duration_ms':       rng.uniform(0.1, 10.0,   n_scan),
        'label':             ['PORT_SCAN'] * n_scan,
    }

    # DDoS: many packets, low variance, but slight noise
    n_ddos = n_attack // 3
    ddos = {
        'packet_count':      rng.integers(50, 600,    n_ddos),
        'byte_count':        rng.integers(3000, 40000, n_ddos),
        'avg_pkt_size':      rng.uniform(60, 80,       n_ddos),
        'pkt_size_variance': rng.uniform(0, 15,        n_ddos),
        'payload_entropy':   rng.uniform(4.0, 7.0,     n_ddos),
        'syn_count':         rng.integers(0, 3,        n_ddos),
        'fin_count':         rng.integers(0, 2,        n_ddos),
        'rst_count':         rng.integers(0, 2,        n_ddos),
        'duration_ms':       rng.uniform(50, 1000,     n_ddos),
        'label':             ['DDOS_SUSPECT'] * n_ddos,
    }

    # Exfiltration: huge byte count, high avg size, high entropy
    n_exfil = n_attack - n_scan - n_ddos
    exfil = {
        'packet_count':      rng.integers(20, 60,      n_exfil),
        'byte_count':        rng.integers(80000, 500000, n_exfil),
        'avg_pkt_size':      rng.uniform(2000, 4500,   n_exfil),
        'pkt_size_variance': rng.uniform(50, 500,      n_exfil),
        'payload_entropy':   rng.uniform(7.5, 8.0,     n_exfil),
        'syn_count':         rng.integers(1, 2,        n_exfil),
        'fin_count':         rng.integers(1, 2,        n_exfil),
        'rst_count':         rng.integers(0, 1,        n_exfil),
        'duration_ms':       rng.uniform(100, 2000,    n_exfil),
        'label':             ['DATA_EXFILTRATION'] * n_exfil,
    }

    frames = []
    for d in [normal, scan, ddos, exfil]:
        frames.append(pd.DataFrame(d))
    df = pd.concat(frames, ignore_index=True).sample(frac=1, random_state=42)
    return df

def main():
    parser = argparse.ArgumentParser(
        description="PacketSentinel Anomaly Detection — ML Training Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Feature Basis (NSL-KDD + CICIDS2017 research datasets):
  packet_count      — NSL-KDD: "count", CICIDS2017: "Total Fwd Packets"
  byte_count        — NSL-KDD: "src_bytes" + "dst_bytes"
  avg_pkt_size      — CICIDS2017: "Fwd Packet Length Mean"
  pkt_size_variance — CICIDS2017: "Packet Length Variance"
  payload_entropy   — Custom (C2 channel detection literature)
  syn_count         — NSL-KDD: "SYN flag count"
  fin_count         — NSL-KDD: "FIN flag count"
  rst_count         — NSL-KDD: "REJ flag count"
  duration_ms       — NSL-KDD: "duration", CICIDS2017: "Flow Duration"
        """
    )
    parser.add_argument('--features', default='flow_features.csv',
                        help='Path to flow features CSV (default: flow_features.csv)')
    parser.add_argument('--output', default=None,
                        help='Save report to file instead of stdout')
    parser.add_argument('--synthetic', action='store_true',
                        help='Use synthetic data instead of CSV (for demo)')
    args = parser.parse_args()

    check_dependencies()

    import pandas as pd
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
    from sklearn.preprocessing import LabelEncoder

    print("=" * 65)
    print("  PacketSentinel — Anomaly Detection ML Training Pipeline")
    print("  Feature basis: NSL-KDD + CICIDS2017 research datasets")
    print("=" * 65)

    # ---- Load data ----------------------------------------------------------
    if args.synthetic or not os.path.exists(args.features):
        if not args.synthetic:
            print(f"\n[!] {args.features} not found. Using synthetic data.\n"
                  f"    Run the engine with --anomaly --export-features to get real data.\n")
        print("[*] Generating synthetic flow features...")
        df = generate_synthetic_features(n_normal=2000, n_attack=500)
        print(f"[*] Generated {len(df)} flows ({len(df[df.label!='NORMAL'])} attack)")
    else:
        print(f"[*] Loading features from {args.features}...")
        df = pd.read_csv(args.features)
        if 'anomaly_type' in df.columns:
            df['label'] = df['anomaly_type'].fillna('NORMAL')
            df['label'] = df['label'].replace('NONE', 'NORMAL')
        elif 'label' not in df.columns:
            print("ERROR: CSV must have 'anomaly_type' or 'label' column")
            sys.exit(1)
        print(f"[*] Loaded {len(df)} flows")

    # ---- Feature matrix -----------------------------------------------------
    FEATURES = [
        'packet_count', 'byte_count', 'avg_pkt_size', 'pkt_size_variance',
        'payload_entropy', 'syn_count', 'fin_count', 'rst_count', 'duration_ms'
    ]

    # Handle missing columns gracefully
    available = [f for f in FEATURES if f in df.columns]
    if len(available) < 5:
        print(f"ERROR: Only found {len(available)} feature columns: {available}")
        sys.exit(1)

    X = df[available].fillna(0).values
    y = df['label'].values

    # ---- Train/test split ---------------------------------------------------
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y)

    print(f"\n[*] Training RandomForestClassifier on {len(X_train)} flows...")
    print(f"    Test set: {len(X_test)} flows")
    print(f"    Classes:  {sorted(set(y))}")

    # ---- Train model --------------------------------------------------------
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        min_samples_leaf=2,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)

    # ---- Evaluate -----------------------------------------------------------
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)

    output_lines = []
    output_lines.append("\n" + "=" * 65)
    output_lines.append("  CLASSIFICATION REPORT")
    output_lines.append("=" * 65)
    output_lines.append(classification_report(y_test, y_pred, zero_division=0))

    output_lines.append(f"  Overall Accuracy: {acc * 100:.2f}%")
    output_lines.append("")

    # Confusion matrix
    output_lines.append("=" * 65)
    output_lines.append("  CONFUSION MATRIX")
    output_lines.append("=" * 65)
    classes = sorted(set(y))
    cm = confusion_matrix(y_test, y_pred, labels=classes)
    header = "              " + "  ".join(f"{c[:8]:>10}" for c in classes)
    output_lines.append(header)
    for i, c in enumerate(classes):
        row = f"  {c[:12]:<12}  " + "  ".join(f"{cm[i][j]:>10}" for j in range(len(classes)))
        output_lines.append(row)
    output_lines.append("")

    # Feature importance
    output_lines.append("=" * 65)
    output_lines.append("  FEATURE IMPORTANCE (sorted by contribution)")
    output_lines.append("=" * 65)
    importances = clf.feature_importances_
    feat_imp = sorted(zip(available, importances), key=lambda x: x[1], reverse=True)
    for feat, imp in feat_imp:
        bar = "#" * int(imp * 50)
        output_lines.append(f"  {feat:<22} {imp:.4f}  {bar}")
    output_lines.append("")

    output_lines.append("=" * 65)
    output_lines.append("  RESEARCH BASIS")
    output_lines.append("=" * 65)
    output_lines.append("  Features derived from:")
    output_lines.append("  • NSL-KDD (Tavallaee et al., 2009)")
    output_lines.append("    SYN/FIN/RST counts, duration, byte volume")
    output_lines.append("  • CICIDS2017 (Sharafaldin et al., 2018)")
    output_lines.append("    Packet length variance, flow duration, avg size")
    output_lines.append("  • Shannon entropy (Bro/Zeek IDS research)")
    output_lines.append("    High entropy on non-TLS ports = C2 channel indicator")
    output_lines.append("")

    report = "\n".join(output_lines)
    print(report)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"[*] Report saved to {args.output}")

    print("\n[*] Training complete.")
    print("    To use with real engine data:")
    print("    ./dpi_engine input.pcap output.pcap --anomaly --stats-json")
    print("    python scripts/train_anomaly_model.py --features flow_features.csv")


if __name__ == '__main__':
    main()
