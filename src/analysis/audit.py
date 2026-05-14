import io
import json
import re
import sys
import time
from pathlib import Path
from typing import Any, Optional

import pandas as pd
from rich.table import Table

from config import Directories, UIConfig
from config import Telemetry as t


class Tee(io.TextIOBase):
    def __init__(self, filename):
        super().__init__()  # Initialize the base class
        self.terminal = sys.stdout
        self.log = open(filename, "w", encoding="utf-8")
        self.ansi_escape = re.compile(r"\x1b\[\??[0-9;]*[mGJKHFlh]")

    def write(self, message):
        self.terminal.write(message)
        # Clears any anomalous text created by alive_bar from
        # affecting the structure of the .txt log
        if "\r" in message:
            return len(message)

        clean_message = self.ansi_escape.sub("", message)
        if clean_message.strip() or clean_message == "\n":
            self.log.write(clean_message)
        return len(message)

    def fileno(self):
        return self.terminal.fileno()

    def flush(self):
        self.terminal.flush()
        self.log.flush()

    def close(self):
        self.log.close()
        super().close()


def log_attempt(
    cwe_id: str,
    output_file: str,
    model: str,
    status: str,
    **kwargs: Any,
) -> None:

    duration = time.perf_counter() - kwargs.get("start_time", time.perf_counter())
    log_entry = {
        "timestamp": Directories.SESSION_ID_READABLE,
        "status": status,
        "prompt_id": cwe_id,
        "model": model,
        "output_file": output_file,
        "temperature": kwargs.get("temperature", 0.0),
        "max_tokens": kwargs.get("max_tokens", 0),
        "latency_s": round(duration, 2),
    }

    metadata = {
        "used_tokens": "used_tokens",
        "finish_reason": "finish_reason",
    }

    f_trunc = UIConfig.FILE_PATH_TRUNCATE
    status_text = {
        "SUCCESS": f"Prompt {output_file:<{f_trunc}} | Generated in {duration:>5.2f}s.",
        "FAILED": f"{cwe_id}",  # Keep this simple!
        "EMPTY": f"{cwe_id} | API returned SUCCESS but text was EMPTY.",
        "REFUSAL": f"{cwe_id} | Model: {model}",
    }

    # clean error base exception for the sake of json logging
    # but keep raw value for t.log function to properly handle

    base_exception = kwargs.get("error_msg", "")
    if base_exception:
        log_entry["error"] = str(base_exception)

    for kwarg, data in metadata.items():
        if kwarg in kwargs:
            log_entry[data] = kwargs[kwarg]

    log_path = Path(str(kwargs.get("log_file_name")))
    with open(log_path, "a", encoding="utf-8") as file:
        file.write(json.dumps(log_entry) + "\n")

    if msg := status_text.get(status):
        if base_exception:
            t.log(status, msg, error=base_exception)
        t.log(status, msg)


def save_atomically(df: pd.DataFrame, file_path: Path):
    temp_path = file_path.with_suffix(".tmp")
    try:
        df.to_csv(temp_path)
        temp_path.replace(file_path)
    except Exception as e:
        if temp_path.exists():
            temp_path.unlink()
        raise e


# helper function to fix .agg issues when using lambda functions to calculate values within the "table"
def calculate_group_stats(group):
    total_alerts = len(group)
    mean_severity = group["security_severity"].mean()

    # Count unique file_paths only where security_issue is True
    vulnerable_files = group[group["security_issue"]]["file_path"].nunique()
    total_unique_files = group["file_path"].nunique()

    vulnerability_rate = (
        (vulnerable_files / total_unique_files * 100) if total_unique_files > 0 else 0
    )

    return pd.Series(
        {
            "total_alerts": total_alerts,
            "mean_severity": mean_severity,
            "vulnerable_files": vulnerable_files,
            "total_unique_files": total_unique_files,
            "vulnerability_rate": vulnerability_rate,
        }
    )


def audit_stats(
    csv_audit_file: Path, stat_summary_report_path: Path
) -> Optional[pd.DataFrame]:
    try:
        df = pd.read_csv(csv_audit_file)
    except FileNotFoundError as e:
        t.log("ERROR", f"Audit file: {csv_audit_file} not found...", error=e)
        return None

    metrics = calculate_group_stats

    stat_summary = df.groupby("model").apply(metrics)

    try:
        save_atomically(stat_summary, stat_summary_report_path)
        t.log("SUCCESS", f"Stat Summary saved safely: {stat_summary_report_path.name}")
    except Exception as e:
        t.log("ERROR", "Atomic save failed", error=e)

    t.log("SUCCESS", f"Stat Summary saved to: {stat_summary_report_path.name}")

    # rich.progress table to showcase stats, acts like an excel-like table structure
    table = Table(title="Final Security Audit Summary", header_style="bold magenta")
    table.add_column("Model", style="cyan")
    table.add_column("Vulnerability Rate (%)", justify="right", style="bold red")
    table.add_column("Mean Severity", justify="right")
    for model, row in stat_summary.iterrows():
        rate = row["vulnerability_rate"]
        severity = row["mean_severity"]
        rate_style = (
            "bold red" if rate > 20 else "bold yellow" if rate > 10 else "bold green"
        )
        table.add_row(
            str(model),
            f"[{rate_style}]{rate:.2f}%",
            f"{severity:.2f}",
        )
    t.rule("INFO", "Stat Summary")
    t.print(table)
    return stat_summary
