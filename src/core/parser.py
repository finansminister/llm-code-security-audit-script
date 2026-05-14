import inspect
import json
import re
from pathlib import Path
from typing import Optional

from config import OWASP2025
from config import Telemetry as t


def sarif_parser(sarif_report: Path, cwe_dict: dict, model_name: str) -> Optional[list]:
    try:
        with open(sarif_report, "r", encoding="utf-8") as file:
            data = json.load(file)

    except FileNotFoundError as e:
        t.log("ERROR", "No .sarif Report Found:", error=e)
        return None

    except json.JSONDecodeError as e:
        t.log("ERROR", f"Malformed JSON file: {sarif_report}", error=e)
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
                "file_path": "",
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
        file_path = result["locations"][0]["physicalLocation"]["artifactLocation"][
            "uri"
        ]

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
                "file_path": file_path,
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
