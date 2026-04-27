"""
A Comparative Semantic Audit of Python Code Generation using CodeQL and SecurityEval

This script orchestrates a batch-processing workflow that:
1. Iterates through a dataset of security-focused prompts.

2. Calls various LLM APIs with controlled parameters.
    2a. Current LLMs: Gemini, Anthropic, Mistral

3. Sanitizes and saves the generated Python code in individual executable .py files.
    3a. .py files are stored in /llm-generated-outputs.

4. A JSON log is created detailing performance and usage metadata for research analysis.

5. Initializes and executes CodeQL static analysis on the outputs and creates a SARIF report on the findings.

6. The SARIF report is parsed and results are displayed in the terminal along with the results of an Anova and T-test.
"""

import json
import random
import re
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Callable

import pandas as pd
from alive_progress import alive_bar
from dotenv import load_dotenv

from codeql_manager import codeql_analysis, codeql_init
from config import Directories, LLMConfig
from descriptive_data import audit_stats, cwe_per_owasp
from llm_api_manager import (
    anthropic_api_call,
    gemini_api_call,
    get_clients,
    mistral_api_call,
)
from owasp_manager import load_owasp_dict
from utils import Tee, anova_test, log_attempt, sanitize_code, sarif_parser


def main_api_call(
    api_call_func: Callable,
    cwe_id: str,
    output_path: Path,
    **kwargs: Any,
) -> None:

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
            return
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


def code_generation_pipeline(
    model: dict, api_parameters: dict, log_file_name: Path
) -> None:

    model_name = model["name"]
    api_client = model["client"]
    model_id = model["id"]
    model_output_dir = model["output_dir"]
    model_api_call = model["api_call_func"]
    temperature = api_parameters["temperature"]
    max_tokens = api_parameters["max_tokens"]
    prompts = []

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

                main_api_call(
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
            except json.JSONDecodeError:
                print(f"Skipping malformed JSON at prompt: {index}")
            except Exception as e:
                print(f"Error processing line {index}: {e}")
            progress_bar()
        # Closes the client if the model allows it
        if hasattr(api_client, "close"):
            api_client.close()


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
def entry_integrity_check():
    if not Path("utils.py").exists():
        print(
            "CRITICAL ERROR: 'utils.py' is missing. ",
            "The orchestration script infrastructure is broken.",
        )
        sys.exit(1)
    try:
        from utils import orchestration_integrity_check
    except ImportError as e:
        print(f"CRITICAL ERROR: Failed to load integrity logic from utils.py: {e}")
        sys.exit(1)

    source_code_files = [
        Path("main.py"),
        Path("utils.py"),
        Path("config.py"),
        Path("codeql_manager.py"),
        Path("llm_api_manager.py"),
        Path("owasp_manager.py"),
        Path("descriptive_data.py"),
    ]
    master_hashes_path = Path("master_hashes.json")

    orchestration_integrity_check(source_code_files, master_hashes_path)


def environment_setup():
    entry_integrity_check()
    # CHECK IF CODEQL IS INSTALLED ON THE SYSTEM
    if shutil.which("codeql") is None:
        print("CRITICAL ERROR: CodeQL CLI not found in System PATH.")
        print("Please install CodeQL or update your PATH variable.")
        exit()

    # LOAD PRELIMINARY FUNCTIONS
    load_dotenv()  # LOAD DATA FROM DOTENV FILE
    Directories.directories_check()  # CREATE ALL REQUIRED DIRECTORIES
    return (LLMConfig.get_api_parameters(), get_clients())


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
    api_parameters, client = environment_setup()
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
        code_generation_pipeline(model, api_parameters, session_jsonl_log_path)

        results, report_path = codeql_and_parse(
            model["name"], model["output_dir"], cwe_dict
        )

        if results:
            stats.extend(results)

        print("\n" + "=" * 50)
        print(f"Model: {model['id']} ({loop_index}/{len(model_configs)}) completed")
        print(f"Vulnerability Report: {report_path}")
        print("=" * 50)

    print("\n*** ALL MODELS PROCESSED - PROCESS FINISHED ***\n")
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
