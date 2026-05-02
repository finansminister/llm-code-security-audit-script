import subprocess
from pathlib import Path

from config import Directories
from src.analysis.audit import sarif_parser


# Creating CodeQl database
def codeql_init(database_dir: Path, output_dir: Path) -> None:
    print(f"Creating CodeQL Database: {database_dir}")
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
        print(f"CodeQL failed: {error.stderr}")
        return


# Starting codeql analysis
def codeql_analysis(database_dir: Path, report_path: Path) -> None:
    print(f"Analyzing Database: {database_dir}")
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
        print(f"Report generated at: {report_path}")
    except subprocess.CalledProcessError as error:
        print(f"CodeQL Analysis failed: {error.stderr}")
        return


def codeql_and_parse(model_name, output_dir, cwe_dict):
    print(f"Starting CodeQL Analysis for {model_name}")

    current_database_dir = Directories.CODEQL_DATABASE_DIR / f"database_{model_name}"

    codeql_init(current_database_dir, output_dir)

    report_name = f"{model_name}_analysis_report.sarif"
    report_path = Directories.RESULTS_DIR / report_name

    print(f"Created .sarif report : {report_name}")
    print(f"At: {report_path}")

    codeql_analysis(current_database_dir, report_path)

    results = sarif_parser(report_path, cwe_dict, model_name)
    return results, report_path
