import inspect
import json
import re
import sys
import time
from pathlib import Path
from typing import Any, Optional

from config import OWASP2025


class Tee:
    def __init__(self, filename):
        self.terminal = sys.stdout
        self.log = open(filename, "w", encoding="utf-8")

    def write(self, message):
        self.terminal.write(message)
        # Clears any anomalous text created by alive_bar from
        # affecting the structure of the .txt log
        clean_message = message.replace("\r", "\n" if "\r" in message else message)
        self.log.write(clean_message)

    def flush(self):
        self.terminal.flush()
        self.log.flush()

    def close(self):
        self.log.close()


def sanitize_code(generated_code: str) -> Optional[str]:

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


def log_attempt(
    cwe_id: str,
    output_file: str,
    model: str,
    status: str,
    **kwargs: Any,
) -> None:

    duration = time.perf_counter() - kwargs.get("start_time", time.perf_counter())
    log_entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
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

    status_messages = {
        "SUCCESS": f"Prompt {output_file} generated in {duration:.2f}s.",
        "FAILED": f"CRITICAL FAILURE on {cwe_id}\nError: {kwargs.get('error_msg', 'Unknown Error')}",
        "EMPTY_RESPONSE": f"API returned SUCCESS but text was EMPTY on {cwe_id}.",
    }

    for kwarg, data in metadata.items():
        if kwarg in kwargs:
            log_entry[data] = kwargs[kwarg]

    log_path = Path(str(kwargs.get("log_file_name")))
    with open(log_path, "a", encoding="utf-8") as file:
        file.write(json.dumps(log_entry) + "\n")

    if msg := status_messages.get(status):
        print(msg)


def sarif_parser(sarif_report: Path, cwe_dict: dict, model_name: str) -> Optional[list]:
    try:
        with open(sarif_report, "r", encoding="utf-8") as file:
            data = json.load(file)

    except FileNotFoundError as e:
        print(f"No .sarif Report Found: {e}")
        return None

    except json.JSONDecodeError:
        print(f"Malformed JSON file: {sarif_report}")
        return None

    runs = data.get("runs", [{}])[0]
    rules = runs.get("tool", {}).get("driver", {}).get("rules", [])

    rules_list = []

    for rule in rules:
        owasp_codes = set()
        cwe_list = []

        rule_id = rule.get("id", [])
        properties = rule.get("properties", {})
        tags = properties.get("tags", [])

        for tag in tags:
            cwe = re.search(r"cwe-(\d+)", tag.lower())
            if cwe:
                cwe_id = f"cwe-{int(cwe.group(1)):03d}"
                cwe_list.append(cwe_id)

        for id in cwe_list:
            a_code = cwe_dict.get(id)
            if a_code:
                owasp_codes.add(a_code)

        rules_list.append(
            {
                "model": model_name,
                "rule_id": rule_id,
                "security_severity": float(properties.get("security-severity", 0.0)),
                "security_issue": len(owasp_codes) > 0,
                "total_cwes": len(owasp_codes),
                "level": rule.get("defaultConfiguration", {}).get("level", "none"),
                "precision": properties.get("precision", "none"),
                "CWEs": cwe_list,
                "OWASP2025_categories": [
                    f"{code}: {OWASP2025.CATEGORIES.get(code)}" for code in owasp_codes
                ],
            }
        )

    return rules_list
