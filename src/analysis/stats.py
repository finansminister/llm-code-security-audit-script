from pathlib import Path
from typing import Any

import pandas as pd
from rich.align import Align
from rich.panel import Panel
from rich.table import Table
from scipy import stats
from scipy.stats import chi2_contingency, kruskal
from statsmodels.stats.multicomp import pairwise_tukeyhsd

from config import Directories, Styles, UIConfig
from config import Telemetry as t

from .audit import audit_stats

S: Any = Styles


def _stat_panel(p_value: float, statistic: float, test_type: str, result_text: str):
    style = S.SIGNIFICANT if p_value < 0.05 else S.INSIGNIFICANT
    t.print(
        Align.center(
            Panel(
                f"Stats: [bold]{statistic:.4f}[/]\n"
                f"p-value: [{style}]{p_value:.4f}[/]\n\n"
                f"[{style}]{result_text}[/]",
                title=f"[{S.INFO}]{test_type}",
                border_style=f"[{S.INFO}]",
                expand=True,
                padding=(1, 2),
            ),
            width=UIConfig.WIDTH,
        )
    )


def chi_squared_test(stat_summary: pd.DataFrame):

    if len(stat_summary) < 2:
        t.log(
            "ERROR",
            "Insufficient data for Chi² (need 2+ models for comparison).",
        )
        return

    vulnerable = stat_summary["vulnerable_files"].tolist()
    clean = (
        stat_summary["total_unique_files"] - stat_summary["vulnerable_files"]
    ).values
    contingency_table = [vulnerable, clean]

    # chi2_contingency tuple outputs: chi2, p, dof, expected
    chi2_table: Any = chi2_contingency(contingency_table)
    chi2 = float(chi2_table.statistic)
    p_val = float(chi2_table.pvalue)
    result_text = (
        "Significant difference in vulnerability rates."
        if p_val < 0.05
        else "Rates are statistically similar."
    )
    _stat_panel(p_val, chi2, "Chi Squared", result_text)


def kruskal_wallis_test(df: pd.DataFrame):
    cwe_tagged = df[df["security_issue"]]

    if len(cwe_tagged) < 2:
        t.log(
            "ERROR",
            "At least two models must have CodeQL alerts for comparison. Kruskal-Wallis skipped...",
        )
        return

    model_groups = [
        group["security_severity"].tolist() for _, group in cwe_tagged.groupby("model")
    ]

    h_stat, p_val = kruskal(*model_groups)

    result_text = (
        "The median severity differs across models."
        if p_val < 0.05
        else "The median severity is statistically similar."
    )
    _stat_panel(p_val, h_stat, "Kruskal Wallis", result_text)


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
    t.log("INFO", "TUKEY HSD POST-HOC TEST")
    t.print(tukey)
    t.log("SUCCESS", "Tukey HSD results saved to:", file_path=tukey_file_name)


def anova_test(csv_audit_file: Path):
    df = pd.read_csv(csv_audit_file)

    cwe_tagged_files = df[df["security_issue"]]

    if cwe_tagged_files.empty:
        t.log("EMPTY", "No CodeQL alerts were found. ANOVA skipped...")
        return

    t.rule("INFO", "MODEL SEVERITY DESCRIPTION")

    desc = cwe_tagged_files.groupby("model")["security_severity"].describe()
    table = Table(title="Security Severity Metrics", header_style=f"{S.INFO}")

    columns = ["Models", "Count", "Mean", "Std", "Min", "Max"]
    for col in columns:
        table.add_column(col)

    for model, row in desc.iterrows():
        table.add_row(
            str(model),
            f"{row['count']:.0f}",
            f"{row['mean']:.2f}",
            f"{row['std']:.2f}",
            f"{row['min']:.1f}",
            f"{row['max']:.1f}",
        )

    model_groups = [
        pd.Series(group["security_severity"]).to_numpy()
        for _, group in cwe_tagged_files.groupby("model")
        if not group.empty
    ]

    # Descibes the statistics regarding the security_severity scores for each CodeQL alert
    if len(model_groups) < 2:
        t.log(
            "ERROR",
            "At least two models must have CodeQL alerts for comparison. ANOVA skipped...",
        )
    f_stat, p_val = stats.f_oneway(*model_groups)

    result_text = (
        "Statistically significant difference found between models."
        if p_val < 0.05
        else "No significant difference found between models."
    )

    _stat_panel(p_val, f_stat, "ANOVA Test", result_text)
    if p_val < 0.05:
        tukeys_hsd(cwe_tagged_files, Directories.RESULTS_DIR)


def run_statistics(stats, final_audit_results):
    audit_dataframe = pd.DataFrame(stats)
    audit_dataframe.to_csv(final_audit_results, index=False)

    t.log("SUCCESS", "Final dataset saved to", file_path=final_audit_results)
    t.rule("INFO", "STATISTICAL AUDIT")

    stat_summary_path = Directories.RESULTS_DIR / f"summary_{final_audit_results.name}"
    summary_dataframe = audit_stats(final_audit_results, stat_summary_path)

    if summary_dataframe is not None:
        chi_squared_test(summary_dataframe)

    anova_test(final_audit_results)
    kruskal_wallis_test(audit_dataframe)

    t.log("SUCCESS", "Statistical audit complete.")
