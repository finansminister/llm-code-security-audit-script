import hashlib
import json
import random
import re
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Callable, Optional

import pandas as pd
from alive_progress import alive_bar
from dotenv import load_dotenv

from audit_manager import Tee, log_attempt, sanitize_code, sarif_parser
from codeql_manager import codeql_analysis, codeql_init
from config import Directories, LLMConfig
from descriptive_data import audit_stats, cwe_per_owasp

# In main.py
from integrity_manager import end_of_process_integrity, llm_output_integrity
from llm_api_manager import (
    anthropic_api_call,
    gemini_api_call,
    get_clients,
    mistral_api_call,
)
from owasp_manager import load_owasp_dict
from stat_generation import anova_test


def main_api_call(
    api_call_func: Callable,
    cwe_id: str,
    output_path: Path,
    **kwargs: Any,
) -> Optional[str]:

    initial_delay, max_retries = 2, 5
    start_time = time.perf_counter()
    output_file = output_path.name
    log_data = {
        "cwe_id": cwe_id,
        "output_file": output_file,
        "start_time": start_time,
        **kwargs,
    }

    for attempt in range(max_retries):
        try:
            response, used_tokens, finish_reason = api_call_func()
            log_data.update(
                {
                    "finish_reason": finish_reason,
                    "used_tokens": used_tokens,
                }
            )
            if not response or str(response).strip() == "":
                log_attempt(**log_data, status="EMPTY_RESPONSE")
                return

            clean_code = str(sanitize_code(response))

            with open(output_path, "w", encoding="utf-8") as file:
                file.write(clean_code)

            log_attempt(**log_data, status="SUCCESS")
            file_hash = hashlib.sha256(clean_code.encode("utf-8")).hexdigest()

            return file_hash
        except Exception as e:
            # Error 429 (Too Many Requests / Resource Exhausted)
            # Error 503 (Service Unavailable / Overloaded)
            error_match = re.search(r"503|429", str(e))
            if error_match and attempt < max_retries - 1:
                http_error = error_match.group()
                # Exponential Backoff + Random Jitter to prevent server issues with multiple simultaneous calls
                delay = (initial_delay * (2**attempt)) + random.uniform(0, 1)
                print(
                    f"Server busy (HTTP: {http_error}). "
                    f"Retrying {output_path} in {delay:.2f}s... "
                    f"(Attempt {attempt + 1}/{max_retries})"
                )
                time.sleep(delay)
            else:
                log_attempt(**log_data, status="FAILED", error_msg=str(e))
                break
    return None


def code_generation_pipeline(
    model: dict, api_parameters: dict, log_file_name: Path
) -> Optional[Path]:

    model_name = model["name"]
    api_client = model["client"]
    model_id = model["id"]
    model_output_dir = model["output_dir"]
    model_api_call = model["api_call_func"]
    temperature = api_parameters["temperature"]
    max_tokens = api_parameters["max_tokens"]

    prompts = []
    file_hashes = {}

    # DATASET ITERATION AND API CALL
    try:
        with open(Directories.DATASET_PATH, "r", encoding="utf-8") as file:
            for line in file:
                prompts.append(json.loads(line))

    except FileNotFoundError:
        print(f"{Directories.DATASET_PATH} not found...")
        return None

    except json.JSONDecodeError as e:
        print(f"Dataset contains malformed JSON: {e}")
        return None

    # stylistic progress bar used to display the progress of code generation
    with alive_bar(
        len(prompts), title=f"Model: {model_id}", bar="classic", spinner="dots_waves2"
    ) as progress_bar:
        for index, data in enumerate(prompts, start=1):
            try:
                cwe_id = (data.get("ID") or "Unknown")[:7]  # CWE-XXX
                dataset_prompt = data.get("Prompt")

                output_file = f"{index}_{cwe_id}_{model_name}_generated_code.py"
                output_file_path = model_output_dir / output_file

                if output_file_path.exists():
                    print(f"Skipping prompt {index}: File already exists.")
                    progress_bar()
                    continue

                file_hash = main_api_call(
                    api_call_func=lambda: model_api_call(
                        api_client,
                        model_id,
                        temperature,
                        max_tokens,
                        dataset_prompt,
                    ),
                    model_id=model_id,
                    cwe_id=cwe_id,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    output_path=output_file_path,
                    log_file_name=log_file_name,
                )

                file_hashes[output_file] = file_hash

            except json.JSONDecodeError:
                print(f"Skipping malformed JSON at prompt: {index}")
            except Exception as e:
                print(f"Error processing line {index}: {e}")
            progress_bar()

    output_manifest = log_file_name.parent / f"{model_name}_output_manifest.json"
    with open(output_manifest, "w", encoding="utf-8") as file:
        json.dump(file_hashes, file, indent=4)
    print(f"Output hash manifest saved to: {output_manifest}")

    # Closes the client if the model allows it
    if hasattr(api_client, "close"):
        api_client.close()

    return output_manifest


def codeql_and_parse(model_name, output_dir, cwe_dict):
    print(f"Starting CodeQL Analysis for {model_name}")

    current_database_dir = Directories.CODEQL_DATABASE_DIR / f"database_{model_name}"

    codeql_init(current_database_dir, output_dir)

    report_name = f"{model_name}_analysis_report.sarif"
    report_path = Directories.SARIF_DIR / report_name

    print(f"Created .sarif report : {report_name}")
    print(f"At: {report_path}")

    codeql_analysis(current_database_dir, report_path)

    results = sarif_parser(report_path, cwe_dict, model_name)
    return results, report_path


# Preliminary integrity check on the off-chance that the utils.py file does not work.
def generate_hashes():
    try:
        from config import SourceCode
        from integrity_manager import orchestration_metadata

        source_code_files = SourceCode.source_code_check()

        master_hashes_path = Path("master_hashes.json")

        return orchestration_metadata(source_code_files, master_hashes_path)

    except ImportError as e:
        print(f"CRITICAL ERROR: Failed to load necessary logic: {e}")
        sys.exit(1)


def environment_setup():

    start_hashes_metadata = generate_hashes()

    if shutil.which("codeql") is None:
        print("CRITICAL ERROR: CodeQL CLI not found in System PATH.")
        print("Please install CodeQL or update your PATH variable.")
        sys.exit(1)

    load_dotenv()
    Directories.directories_check()
    return (LLMConfig.get_api_parameters(), get_clients(), start_hashes_metadata)


def run_statistics(stats, final_audit_results):
    dataframe = pd.DataFrame(stats)
    dataframe.to_csv(final_audit_results, index=False)
    print(f"Final dataset saved to {final_audit_results.name}")
    print("\n" + "=" * 60)
    print("=== BEGINNING STATISTICAL AUDIT ===")
    print("=" * 60)

    stat_summary_path = (
        Directories.CSV_AUDITS_DIR / f"summary_{final_audit_results.name}"
    )
    audit_stats(final_audit_results, stat_summary_path)
    anova_test(final_audit_results)


def orchestration(session_jsonl_log_path, final_audit_results):
    api_parameters, client, start_hashes_metadata = environment_setup()
    cwe_dict = load_owasp_dict(Directories.OWASP_MAP_PATH)
    cwe_per_owasp(cwe_dict, "OWASP_2025_Mapping", session_jsonl_log_path.parent)
    # Api Call Functions
    api_call_funcs = {
        "gemini": gemini_api_call,
        "anthropic": anthropic_api_call,
        "mistral": mistral_api_call,
    }

    model_configs = LLMConfig.model_cfg(client, api_call_funcs)

    stats = []
    for loop_index, model in enumerate(model_configs, start=1):
        output_manifest = code_generation_pipeline(
            model, api_parameters, session_jsonl_log_path
        )

        results, report_path = codeql_and_parse(
            model["name"], model["output_dir"], cwe_dict
        )

        if output_manifest is None:
            print(f"CRITICAL: Pipeline failed for {model['id']}. Skipping analysis.")
            continue

        llm_output_integrity(output_manifest, model["output_dir"])

        if results:
            stats.extend(results)

        print("\n" + "=" * 50)
        print(f"Model: {model['id']} ({loop_index}/{len(model_configs)}) completed")
        print(f"Vulnerability Report: {report_path}")
        print("=" * 50)

    print("\n*** ALL MODELS PROCESSED - PROCESS FINISHED ***\n")

    print("\n" + "=" * 60)
    print("=== FINAL SYSTEM STATE VALIDATION ===")

    final_hashes_metadata = generate_hashes()
    end_of_process_integrity(final_hashes_metadata, start_hashes_metadata)

    print("=" * 60 + "\n")

    if stats:
        run_statistics(stats, final_audit_results)


if __name__ == "__main__":
    session_log_dir = (
        Directories.SESSION_DIR / f"session-logs-{time.strftime('%Y%m%d_%H%M%S')}"
    )
    session_log_dir.mkdir(parents=True, exist_ok=True)
    session_jsonl_log_path = session_log_dir / "code_generation_log.jsonl"
    final_audit_results = (
        Directories.CSV_AUDITS_DIR
        / f"final_audit_results_{time.strftime('%Y%m%d_%H%M%S')}.csv"
    )
    session_terminal_output = session_log_dir / "session_terminal_output.txt"

    tee = Tee(session_terminal_output)
    original_stdout = sys.stdout
    sys.stdout = tee

    try:
        orchestration(session_jsonl_log_path, final_audit_results)
    finally:
        sys.stdout = original_stdout
        tee.close()
        print(f"\nSession Complete. Log saved to {session_terminal_output}")

    sys.exit(0)
