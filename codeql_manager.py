import subprocess
from pathlib import Path

"""

codeql_init():
    Initializes CodeQL and creates the database.

codeql_analysis():
    Analyzes the code output and creats a SARIF report.

"""


# Creating CodeQl database
def codeql_init(database_dir: Path, output_dir: Path) -> None:
    if database_dir.exists():
        print(f"Database: {database_dir} already exists...")
        return

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
