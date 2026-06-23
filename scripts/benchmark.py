#!/usr/bin/env python3
"""
benchmark.py — Throughput benchmark for DPI Engine
Measures single-threaded and multi-threaded performance, prints table.
"""

import subprocess
import time
import statistics
import os
import sys
import json

SIMPLE_EXE = './dpi_simple'
MT_EXE     = './dpi_engine'
INPUT      = 'test_data/test_large.pcap'
OUTPUT_DIR = 'test_data'
RUNS       = 3

if sys.platform == 'win32':
    SIMPLE_EXE = 'dpi_simple.exe'
    MT_EXE     = 'dpi_engine.exe'

def parse_kpps(output):
    """Extract Kpps value from engine output."""
    for line in output.split('\n'):
        if 'Kpps' in line or 'kpps' in line:
            parts = line.split()
            for i, p in enumerate(parts):
                if 'Kpps' in p or 'kpps' in p:
                    try:
                        # The number is before "Kpps"
                        return float(parts[i-1])
                    except (ValueError, IndexError):
                        pass
    return 0.0

def parse_elapsed(output):
    """Extract elapsed seconds from engine output."""
    for line in output.split('\n'):
        if 'packets in' in line and 's' in line:
            parts = line.split()
            for i, p in enumerate(parts):
                if 'in' == p and i + 1 < len(parts):
                    try:
                        return float(parts[i+1].rstrip('s'))
                    except ValueError:
                        pass
    return 0.0

def parse_total_packets(output):
    """Extract total packet count."""
    for line in output.split('\n'):
        if 'Read' in line and 'packets' in line:
            parts = line.split()
            for i, p in enumerate(parts):
                if p == 'Read' and i + 1 < len(parts):
                    try:
                        return int(parts[i+1])
                    except ValueError:
                        pass
    return 0

def run_engine(cmd, run_idx):
    """Run engine, capture output, return stats dict."""
    output_file = f'{OUTPUT_DIR}/bench_output_{run_idx}.pcap'
    full_cmd = cmd + [INPUT, output_file, '--no-stats']

    start = time.perf_counter()
    try:
        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
        elapsed = time.perf_counter() - start
        combined = result.stdout + result.stderr

        total_pkts = parse_total_packets(combined)
        kpps = parse_kpps(combined) or (total_pkts / 1000.0 / elapsed if elapsed > 0 else 0)

        return {
            'elapsed':   elapsed,
            'kpps':      kpps,
            'packets':   total_pkts,
            'success':   result.returncode == 0,
            'output':    combined
        }
    except subprocess.TimeoutExpired:
        return {'elapsed': 120, 'kpps': 0, 'packets': 0, 'success': False, 'output': 'TIMEOUT'}
    except FileNotFoundError:
        return {'elapsed': 0, 'kpps': 0, 'packets': 0, 'success': False, 'output': 'EXE NOT FOUND'}

def benchmark_config(name, cmd, runs=RUNS):
    """Benchmark a config, run N times, return stats."""
    print(f"  Running {name} ({runs} runs)...", end='', flush=True)
    results = []
    for i in range(runs):
        r = run_engine(cmd, i)
        if r['success']:
            results.append(r['kpps'])
            print(f" {r['kpps']:.1f}", end='', flush=True)
        else:
            print(f" FAIL({r['output'][:30]})", end='', flush=True)
    print()

    if not results:
        return {'mean': 0, 'stddev': 0, 'min': 0, 'max': 0}

    return {
        'mean':   statistics.mean(results),
        'stddev': statistics.stdev(results) if len(results) > 1 else 0.0,
        'min':    min(results),
        'max':    max(results),
    }

def main():
    print("=" * 60)
    print("DPI Engine Throughput Benchmark")
    print("=" * 60)

    # Check input file exists
    if not os.path.exists(INPUT):
        print(f"[Error] Input file not found: {INPUT}")
        print("Run: python scripts/generate_test_pcap.py first")
        sys.exit(1)

    # Check engines
    if not os.path.exists(SIMPLE_EXE):
        print(f"[Error] {SIMPLE_EXE} not found. Build first.")
        sys.exit(1)

    print(f"\nInput: {INPUT}")
    import struct
    with open(INPUT, 'rb') as f:
        f.seek(0, 2)
        size = f.tell()
    print(f"Size:  {size / 1024 / 1024:.1f} MB")
    print()

    configs = [
        ("Single-threaded",     [SIMPLE_EXE]),
    ]

    if os.path.exists(MT_EXE):
        configs += [
            ("MT (1 LB × 1 FP)",  [MT_EXE, '--lbs', '1', '--fps', '1']),
            ("MT (1 LB × 2 FP)",  [MT_EXE, '--lbs', '1', '--fps', '2']),
            ("MT (2 LB × 2 FP)",  [MT_EXE, '--lbs', '2', '--fps', '2']),
            ("MT (2 LB × 4 FP)",  [MT_EXE, '--lbs', '2', '--fps', '4']),
        ]

    results = {}
    for name, cmd in configs:
        results[name] = benchmark_config(name, cmd)

    # Print results table
    print("\n")
    print("┌─────────────────────────┬──────────┬──────────┬──────────┬──────────┐")
    print("│ Configuration           │ Mean Kpps│  Std Dev │  Min Kpps│  Max Kpps│")
    print("├─────────────────────────┼──────────┼──────────┼──────────┼──────────┤")

    baseline = results.get("Single-threaded", {}).get("mean", 1) or 1
    for name, r in results.items():
        speedup = r['mean'] / baseline if baseline > 0 else 0
        suffix = f" ({speedup:.1f}×)" if name != "Single-threaded" else ""
        name_col = (name + suffix)[:25].ljust(25)
        print(f"│ {name_col} │ {r['mean']:>8.1f} │ {r['stddev']:>8.2f} │"
              f" {r['min']:>8.1f} │ {r['max']:>8.1f} │")

    print("└─────────────────────────┴──────────┴──────────┴──────────┴──────────┘")

    # Save results JSON
    out_path = 'test_data/benchmark_results.json'
    with open(out_path, 'w') as f:
        json.dump({
            name: {**r, 'speedup': r['mean'] / baseline}
            for name, r in results.items()
        }, f, indent=2)
    print(f"\nResults saved to {out_path}")
    print("\nFill these numbers into your README resume bullets!")

if __name__ == '__main__':
    main()
