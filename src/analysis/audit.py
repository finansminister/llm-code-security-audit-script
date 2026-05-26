import io
import json
import re
import sys
import time
from pathlib import Path
from typing import Any, Optional

import pandas as pd
from rich.align import Align
from rich.columns import Columns
from rich.table import Table

from config import Directories, LLMConfig, Styles, UIConfig
from config import Telemetry as t

S: Any = Styles


class Tee(io.TextIOBase):
    def __init__(self, filename, mode="w"):
        super().__init__()  # Initialize the base class
        self.terminal = sys.stdout
        self.log = open(filename, mode, encoding="utf-8")
        self.ansi_escape = re.compile(r"\x1b\[\??[0-9;]*[mGJKHFlh]")

    def write(self, message):
        self.terminal.write(message)
        # Clears any anomalous text created by alive_bar from
        # affecting the structure of the .txt log
        if "\r" in message:
            return len(message)

        clean_message = self.ansi_escape.sub("", message)
        if clean_message.strip() or clean_message == "\n":
            try:
                self.log.write(clean_message)
            except ValueError:
                pass  # prevents error messages when closing script during final "finally" block
        return len(message)

    def fileno(self):
        return self.terminal.fileno()

    def flush(self):
        self.terminal.flush()
        if self.log and not self.log.closed:
            try:
                self.log.flush()
            except ValueError:
                pass  # prevents the splitter from trying to flush the contents after the terminal has been closed

    def close(self):
        self.flush()  # making sure it flushes before the terminal closes to prevent error messages
        if self.log and not self.log.closed:
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
        "session_id": Directories.SESSION_ID_READABLE,
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
    security_issue = group[
        group["security_issue"]
    ]  # Security issue is a boolian tag i added to keep track of security alerts vs non-security alerts.
    mean_severity = (
        security_issue["security_severity"].mean() if not security_issue.empty else 0.0
    )

    # Count unique file_paths only where security_issue is True
    vulnerable_files = security_issue["file_path"].nunique()
    total_unique_files = 121

    vulnerability_rate = (
        (vulnerable_files / total_unique_files * 100) if total_unique_files > 0 else 0
    )

    mean_latency = group["latency_s"].mean() if "latency_s" in group.columns else 0.0

    return pd.Series(
        {
            "total_alerts": total_alerts,
            "mean_severity": mean_severity,
            "vulnerable_files": vulnerable_files,
            "total_unique_files": total_unique_files,
            "vulnerability_rate": vulnerability_rate,
            "mean_latency": mean_latency,
        }
    )


def audit_stats(
    csv_audit_file: Path,
    stat_summary_report_path: Path,
    jsonl_log_file: Path,
) -> Optional[pd.DataFrame]:
    try:
        df = pd.read_csv(csv_audit_file)
    except FileNotFoundError as e:
        t.log("ERROR", f"Audit file: {csv_audit_file} not found...", error=e)
        return None

    try:
        jsonl_df = pd.read_json(jsonl_log_file, lines=True)
    except FileNotFoundError as e:
        t.log(
            "ERROR", f"Code generation log file: {jsonl_log_file} not found...", error=e
        )
        return None

    model_name_map = {
        f"{LLMConfig.ANTHROPIC_MODEL}": "anthropic",
        f"{LLMConfig.GEMINI_MODEL}": "gemini",
        f"{LLMConfig.MISTRAL_MODEL}": "mistral",
        f"{LLMConfig.META_MODEL}": "meta",
    }

    jsonl_df["mapped_model"] = jsonl_df["model"].replace(model_name_map)
    grouped_df: Any = jsonl_df.groupby("mapped_model", as_index=True).mean(
        numeric_only=True
    )

    latency_series = grouped_df["latency_s"]
    latency_dict = latency_series.to_dict()

    df["latency_s"] = df["model"].map(latency_dict)

    stat_summary = df.groupby("model").apply(calculate_group_stats)

    try:
        save_atomically(stat_summary, stat_summary_report_path)
        t.log("SUCCESS", "Stat Summary saved:", file_path=stat_summary_report_path)
    except Exception as e:
        t.log("ERROR", "Atomic save failed", error=e)

    # rich.progress table to showcase stats, acts like an excel-like table structure
    table = Table(
        title="Final Security Audit Summary",
        caption=f"Session ID: {Directories.SESSION_ID_READABLE}",
        header_style="bold magenta",
        title_justify="center",
        caption_justify="center",
    )
    table.add_column("Model", style=f"{S.FILE}")
    table.add_column("Vulnerability Rate", justify="right")
    table.add_column("Mean Severity", justify="right")
    table.add_column("Mean Latency", justify="right")
    for model, row in stat_summary.iterrows():
        rate = row["vulnerability_rate"]
        severity = row["mean_severity"]
        latency = row["mean_latency"]
        rate_style = (
            "bold red" if rate > 20 else "bold yellow" if rate > 10 else "bold green"
        )
        table.add_row(
            str(model),
            f"[{rate_style}]{rate:.2f}%",
            f"{severity:.2f}",
            f"{latency:.2f}",
        )
    t.rule("INFO", "Stat Summary")
    t.print("\n")
    centered_table = Columns([table], align="center", expand=False)
    t.print(Align.center(centered_table))
    t.print("\n")
    return stat_summary
