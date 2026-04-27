import time
from collections import Counter
from pathlib import Path

import pandas as pd


def audit_stats(csv_audit_file: Path, stat_summary_report_path: Path):
    try:
        df = pd.read_csv(csv_audit_file)
    except FileNotFoundError:
        print(f"Audit file: {csv_audit_file} not found...")
        return

    stat_summary = (
        df.groupby("model")
        .agg(
            total_cwes=("total_cwes", "sum"),
            mean_security_severity=("security_severity", "mean"),
            cwe_tagged_files=("security_issue", "sum"),
            all_files=("model", "count"),
        )
        .assign(
            pct_of_alerts=lambda _stat: (
                _stat["cwe_tagged_files"] / _stat["all_files"] * 100
            )
        )
    )

    stat_summary.to_csv(stat_summary_report_path)
    print(f"Stat Summary saved to: {stat_summary_report_path}")
    print(f"\n{stat_summary.round(2)}")
    return stat_summary


def cwe_per_owasp(cwe_dict: dict, cwe_dict_file_name: str, summary_dir: Path) -> None:
    metadata_path = summary_dir / "cwe_per_owasp.txt"
    counts = Counter(cwe_dict.values())

    print(f"Metadata saved to: {metadata_path}")

    with open(metadata_path, "w", encoding="utf-8") as file:
        file.write("=== EXPERIMENT METADATA ===\n")
        file.write(f"Source: {cwe_dict_file_name}\n")
        file.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        file.write("=== CWE MAPPING DISTRIBUTION ===\n")
        for a_code, count in sorted(counts.items()):
            file.write(f"{a_code}: {count:>3} CWEs\n")
