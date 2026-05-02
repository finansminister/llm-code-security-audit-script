from pathlib import Path
from typing import Any

import pandas as pd
from scipy import stats
from scipy.stats import chi2_contingency, kruskal
from statsmodels.stats.multicomp import pairwise_tukeyhsd

from audit_manager import audit_stats
from config import Directories


def chi_squared_test(stat_summary: pd.DataFrame):

    if len(stat_summary) < 2:
        print(
            "At least two models must have CodeQL alerts for comparison. Chi-Squared skipped..."
        )

    vulnerable = stat_summary["vulnerable_files"].tolist()
    clean = (
        stat_summary["total_unique_files"] - stat_summary["vulnerable_files"]
    ).values
    contingency_table = [vulnerable, clean]

    # chi2_contingency tuple outputs: chi2, p, dof, expected
    chi2_table: Any = chi2_contingency(contingency_table)
    chi2 = float(chi2_table.statistic)
    p_val = float(chi2_table.pvalue)

    print(f"Chi-Squared Statistic: {chi2:.4f}")
    print(f"p-value: {p_val:.4f}")

    if p_val < 0.05:
        print(
            "Significant statistical difference found, model choice affects the probability of vulnerabilities."
        )
    else:
        print("No significat statistical difference in rates of vulnerabilities.")


def kruskal_wallis_test(df: pd.DataFrame):
    cwe_tagged = df[df["security_issue"]]

    if len(cwe_tagged) < 2:
        print(
            "At least two models must have CodeQL alerts for comparison. Kruskal-Wallis skipped..."
        )

    model_groups = [
        group["security_severity"].tolist() for _, group in cwe_tagged.groupby("model")
    ]

    h_stat, p_val = kruskal(*model_groups)

    print(f"H-statistic: {h_stat:.4f}")
    print(f"p-value: {p_val:.4f}")

    if p_val < 0.05:
        print("The median severity differs across models.")
    else:
        print("The median severity is statistically similar.")


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
    audit_dataframe = pd.DataFrame(stats)
    audit_dataframe.to_csv(final_audit_results, index=False)
    print(f"Final dataset saved to {final_audit_results.name}")
    print("\n" + "=" * 60)
    print("=== BEGINNING STATISTICAL AUDIT ===")
    print("=" * 60)

    stat_summary_path = (
        Directories.CSV_AUDITS_DIR / f"summary_{final_audit_results.name}"
    )
    summary_dataframe = audit_stats(final_audit_results, stat_summary_path)

    if summary_dataframe is not None:
        chi_squared_test(summary_dataframe)

    anova_test(final_audit_results)

    kruskal_wallis_test(audit_dataframe)
