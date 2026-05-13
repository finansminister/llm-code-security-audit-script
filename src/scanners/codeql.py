import subprocess
from pathlib import Path
from typing import Any

from config import Directories, Styles
from config import Telemetry as t
from src.analysis.audit import sarif_parser

S: Any = Styles


# Creating CodeQl database
def codeql_init(database_dir: Path, output_dir: Path) -> None:
    with t.status("INFO", "Initializing CodeQL Database..."):
        try:
            subprocess.run(
                [
                    "codeql",
                    "database",
                    "create",
                    str(database_dir),
                    "--language=python",
                    f"--source-root={output_dir}",
                    "--overwrite",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as error:
            t.log("ERROR", "CodeQL failed:", error=error)
            return


# Starting codeql analysis
def codeql_analysis(database_dir: Path, report_path: Path) -> None:
    with t.status("INFO", f"Analyzing CodeQL Database: {database_dir}"):
        try:
            subprocess.run(
                [
                    "codeql",
                    "database",
                    "analyze",
                    "--quiet",
                    str(database_dir),
                    "python-security-and-quality.qls",
                    "--format=sarifv2.1.0",
                    f"--output={report_path}",
                    "--no-rerun",
                ],
                check=True,
                capture_output=True,
            )
            t.log("INFO", "Report generated at:", file_path=report_path)
        except subprocess.CalledProcessError as error:
            t.log("ERROR", "CodeQL analysis failed:", error=error)
            return


def codeql_and_parse(model_name, output_dir, cwe_dict):
    t.log("INFO", "Starting CodeQL Analysis for:", file_path=model_name)

    current_database_dir = Directories.CODEQL_DATABASE_DIR / f"database_{model_name}"

    codeql_init(current_database_dir, output_dir)

    report_name = f"{model_name}_analysis_report.sarif"
    report_path = Directories.RESULTS_DIR / report_name

    t.log("INFO", "Created static analysis report (.sarif):", file_path=report_path)

    codeql_analysis(current_database_dir, report_path)

    results = sarif_parser(report_path, cwe_dict, model_name)
    return results, report_path
