from pathlib import Path

import pandas as pd
from scipy import stats
from statsmodels.stats.multicomp import pairwise_tukeyhsd

from audit_manager import audit_stats
from config import Directories


def tukeys_hsd(cwe_tagged_files, tukey_output_path: Path):
    tukey = pairwise_tukeyhsd(
        endog=cwe_tagged_files["security_severity"],
        groups=cwe_tagged_files["model"],
        alpha=0.05,
    )
    tukey_df = pd.DataFrame(
        data=tukey.summary().data[1:], columns=tukey.summary().data[0]
    )

    tukey_file_name = tukey_output_path / "tukey_hsd_results.csv"
    tukey_df.to_csv(tukey_file_name, index=False)
    print("\n--- TUKEY HSD POST-HOC TEST ---")
    print(tukey)
    print(f"Tukey HSD results saved to: {tukey_file_name.name}")


def anova_test(csv_audit_file: Path):
    try:
        df = pd.read_csv(csv_audit_file)
    except FileNotFoundError:
        print(f"Audit file: {csv_audit_file} not found...")
        return

    cwe_tagged_files = df[df["security_issue"]]

    if cwe_tagged_files.empty:
        print("No CodeQL alerts were found. ANOVA skipped...")
        return

    print("\n--- MODEL STATISTICS (Vulnerable Files Only) ---")
    print(cwe_tagged_files.groupby("model")["security_severity"].describe())

    model_groups = [
        pd.Series(group["security_severity"]).to_numpy()
        for _, group in cwe_tagged_files.groupby("model")
        if not group.empty
    ]

    # Descibes the statistics regarding the security_severity scores for each CodeQL alert
    if len(model_groups) < 2:
        print(
            "At least two models must have CodeQL alerts for comparison. ANOVA skipped..."
        )
    f_stat, p_val = stats.f_oneway(*model_groups)

    print(f"\nANOVA Test Results:\nF-statistic: {f_stat:.4f}\np-value: {p_val:.4f}")

    if p_val < 0.05:
        print(
            "Statistically significant difference found between models (p-value < 0.05)"
        )
        print("Starting Tukey HSD test to determine the difference maker...")
        tukeys_hsd(cwe_tagged_files, Directories.CSV_AUDITS_DIR)
    else:
        print("No significant difference found between models (p-value > 0.05)")
        return


def run_statistics(stats, final_audit_results):
    dataframe = pd.DataFrame(stats)
    dataframe.to_csv(final_audit_results, index=False)
    print(f"Final dataset saved to {final_audit_results.name}")
    print("\n" + "=" * 60)
    print("=== BEGINNING STATISTICAL AUDIT ===")
    print("=" * 60)

    stat_summary_path = (
        Directories.CSV_AUDITS_DIR / f"summary_{final_audit_results.name}"
    )
    audit_stats(final_audit_results, stat_summary_path)
    anova_test(final_audit_results)
