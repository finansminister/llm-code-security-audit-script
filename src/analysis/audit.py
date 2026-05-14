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
        "error_msg": "error",
        "finish_reason": "finish_reason",
    }

    f_trunc = UIConfig.FILE_PATH_TRUNCATE
    status_text = {
        "SUCCESS": f"Prompt {output_file:<{f_trunc}} | Generated in {duration:>5.2f}s.",
        "FAILED": f"CRITICAL FAILURE on {cwe_id:<{f_trunc}} | Error: {str(kwargs.get('error_msg', 'Unknown'))[: UIConfig.ERR_MSG_TRUNCATE]}",
        "EMPTY": f"EMPTY RESPONSE on {cwe_id:<{f_trunc}} | API returned SUCCESS but text was EMPTY.",
        "REFUSAL": f"SAFETY REFUSAL for {cwe_id:<{f_trunc}} | Model: {model}",
    }

    for kwarg, data in metadata.items():
        if kwarg in kwargs:
            log_entry[data] = kwargs[kwarg]

    log_path = Path(str(kwargs.get("log_file_name")))
    with open(log_path, "a", encoding="utf-8") as file:
        file.write(json.dumps(log_entry) + "\n")

    if msg := status_text.get(status):
        t.log(status, msg)


def audit_stats(
    csv_audit_file: Path, stat_summary_report_path: Path
) -> Optional[pd.DataFrame]:
    try:
        df = pd.read_csv(csv_audit_file)
    except FileNotFoundError as e:
        t.log("ERROR", f"Audit file: {csv_audit_file} not found...", error=e)
        return None

    stat_summary = (
        df.groupby("model")
        .agg(
            total_alerts=("security_issue", "count"),
            mean_severity=("security_severity", "mean"),
            vulnerable_files=(
                "file_path",
                lambda x: df.loc[x.index][df["security_issue"]]["file_path"].nunique(),
            ),
            total_unique_files=("file_path", "nunique"),
        )
        .assign(
            vulnerability_rate=lambda x: (
                x["vulnerable_files"] / x["total_unique_files"] * 100
            )
        )
    )
    stat_summary.to_csv(stat_summary_report_path)
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
