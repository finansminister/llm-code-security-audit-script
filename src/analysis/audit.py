import inspect
import json
import re
import sys
import time
from pathlib import Path
from typing import Any, Optional

import pandas as pd
from rich.table import Table

from config import OWASP2025, Directories, UIConfig
from config import Telemetry as t


class Tee:
    def __init__(self, filename):
        self.terminal = sys.stdout
        self.log = open(filename, "w", encoding="utf-8")
        self.ansi_escape = re.compile(r"\x1b\[[0-9;]*[mGJKHF]")

    def write(self, message):
        self.terminal.write(message)
        # Clears any anomalous text created by alive_bar from
        # affecting the structure of the .txt log
        if any(char in message for char in ("\r", "\x1b")):
            return

        clean_message = self.ansi_escape.sub("", message)
        if clean_message.strip() or clean_message == "\n":
            self.log.write(clean_message)

    def fileno(self):
        return self.terminal.fileno()

    def flush(self):
        self.terminal.flush()
        self.log.flush()

    def close(self):
        self.log.close()


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


def sarif_parser(sarif_report: Path, cwe_dict: dict, model_name: str) -> Optional[list]:
    try:
        with open(sarif_report, "r", encoding="utf-8") as file:
            data = json.load(file)

    except FileNotFoundError as e:
        t.log("ERROR", f"No .sarif Report Found: {e}")
        return None

    except json.JSONDecodeError:
        t.log("ERROR", f"Malformed JSON file: {sarif_report}")
        return None

    runs = data.get("runs", [{}])[0]
    rules_metadata = {
        rule["id"]: rule
        for rule in runs.get("tool", {}).get("driver", {}).get("rules", [])
    }
    results = runs.get("results", [])
    findings = []

    if not results:
        return [
            {
                "model": model_name,
                "rule_id": "none",
                "security_severity": 0.0,
                "security_issue": False,
                "total_cwes": 0,
                "level": "none",
                "precision": "none",
                "CWEs": [],
                "OWASP2025_categories": [],
            }
        ]

    for result in results:
        rule_id = result.get("ruleId", [])
        rule_obj = rules_metadata.get(rule_id, {})
        properties = rule_obj.get("properties", {})
        default_config = rule_obj.get("defaultConfiguration", {})
        tags = properties.get("tags", [])

        owasp_codes = set()
        cwe_list = []

        for tag in tags:
            cwe = re.search(r"cwe-(\d+)", tag.lower())
            if cwe:
                cwe_id = f"cwe-{int(cwe.group(1)):03d}"
                cwe_list.append(cwe_id)
                a_code = cwe_dict.get(cwe_id)
                if a_code:
                    owasp_codes.add(a_code)

        findings.append(
            {
                "model": model_name,
                "rule_id": rule_id,
                "security_severity": float(properties.get("security-severity", 0.0)),
                "security_issue": len(owasp_codes) > 0,
                "total_cwes": len(owasp_codes),
                "level": default_config.get("level", "none"),
                "precision": properties.get("precision", "none"),
                "CWEs": cwe_list,
                "OWASP2025_categories": [
                    f"{a_code}: {OWASP2025.get_owasp_name(a_code)}"
                    for a_code in owasp_codes
                ],
            }
        )

    return findings


def sanitize_code(generated_code: str) -> Optional[str]:

    if generated_code.startswith("Refusal:") or generated_code.startswith("ERROR:"):
        return None

    pattern = r"```(?:python|py)?\s*\n?(.*?)```"
    matches = re.findall(pattern, generated_code, re.DOTALL | re.IGNORECASE)

    if matches:
        best_match = max(matches, key=len)
        return inspect.cleandoc(best_match)

    # Fallback Filters
    # checks if there are any stray "python" texts at the top of the code block the llm didnt indent properly
    lines = generated_code.strip().splitlines()
    if lines and lines[0].strip().lower() in {"python", "py", "python3"}:
        lines = lines[1:]

    # cleans any stray backticks at the top or bottom of the code block but not filtering anything inside the code block
    cleaned = "\n".join(lines).strip().strip("`").strip()

    # inspect.cleandoc() preserves the indentation of the python code
    return inspect.cleandoc(cleaned.strip())
