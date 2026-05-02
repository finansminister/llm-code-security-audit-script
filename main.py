import json
import shutil
import sys
from pathlib import Path

from dotenv import load_dotenv
from wakepy import keep

from config import Directories, LLMConfig, UIConfig
from src.analysis import Tee, run_statistics
from src.core import (
    end_of_process_integrity,
    generate_hashes,
    llm_output_integrity,
)
from src.llm import (
    anthropic_api_call,
    code_generation_pipeline,
    gemini_api_call,
    get_clients,
    meta_api_call,
    mistral_api_call,
)
from src.scanners import codeql_and_parse, cwe_per_owasp, load_owasp_dict


def environment_setup() -> tuple:

    start_hashes_metadata = generate_hashes()

    if shutil.which("codeql") is None:
        print("CRITICAL ERROR: CodeQL CLI not found in System PATH.")
        print("Please install CodeQL or update your PATH variable.")
        sys.exit(1)

    load_dotenv()
    Directories.directories_check()
    return (LLMConfig.get_api_parameters(), get_clients(), start_hashes_metadata)


def orchestration(
    session_jsonl_log_path: Path, final_audit_results_path: Path, test_limit=None
) -> None:
    api_parameters, client, start_hashes_metadata = environment_setup()
    cwe_dict = load_owasp_dict(Directories.OWASP_MAP_PATH)
    cwe_per_owasp(cwe_dict, "OWASP_2025_Mapping", session_jsonl_log_path.parent)
    # Api Call Functions
    api_call_funcs = {
        "gemini": gemini_api_call,
        "anthropic": anthropic_api_call,
        "mistral": mistral_api_call,
        "meta": meta_api_call,
    }

    model_configs = LLMConfig.model_cfg(client, api_call_funcs)

    stats = []
    for loop_index, model in enumerate(model_configs, start=1):
        print(
            f"\n>>> Starting Model: {model['id']} ({loop_index}/{len(model_configs)})"
        )
        output_manifest = code_generation_pipeline(
            model, api_parameters, session_jsonl_log_path, test_limit=test_limit
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

    width = UIConfig.TERMINAL_WIDTH
    print("\n*** ALL MODELS PROCESSED - CODE GENERATION FINISHED ***\n")

    print("\n" + "=" * width)
    print("=== FINAL SYSTEM STATE VALIDATION ===")

    final_hashes_metadata = generate_hashes()
    end_of_process_integrity(final_hashes_metadata, start_hashes_metadata)

    print("=" * width + "\n")

    if stats:
        run_statistics(stats, final_audit_results_path)


if __name__ == "__main__":
    TEST_MODE = False
    LIMIT = 3 if TEST_MODE else None

    session_log_dir = Directories.OUTPUT_DIR / "session-logs"
    session_log_dir.mkdir(parents=True, exist_ok=True)
    session_jsonl_log_path = session_log_dir / "code_generation_log.jsonl"
    final_audit_results_path = (
        Directories.RESULTS_DIR / f"final_audit_results_{Directories.SESSION_ID}.csv"
    )
    session_terminal_output = session_log_dir / "session_terminal_output.txt"

    width = UIConfig.TERMINAL_WIDTH
    f_pad = UIConfig.FILE_NAME_PAD
    with keep.running():
        tee = Tee(session_terminal_output)
        original_stdout = sys.stdout
        sys.stdout = tee

        print("\n" + "=" * width)
        print(f"{'TEST RUN ACTIVE' if TEST_MODE else 'FULL AUDIT START'}".center(width))
        print(
            f"Sample Size: {LIMIT if TEST_MODE else '121'} prompts per model".center(
                width
            )
        )
        print("=" * width + "\n")

        print("\n" + "=" * width)
        print("ORCHESTRATION SCRIPT START".center(width))
        print(f"Timestamp: {Directories.SESSION_ID_READABLE}".center(width))

        if Directories.MASTER_HASH_PATH.exists():
            with open(Directories.MASTER_HASH_PATH, "r") as file:
                master = json.load(file)

            print(f"Master Baseline Date: {master.get('date')}".center(width))
            print("-" * width)

            print(f"{'AUTHORIZED SOURCE FILE':<{f_pad}} | {'SHA-256 (SNIPPET)'}")
            print("-" * width)

            for filename, full_hash in master.items():
                if filename != "date":
                    print(f"{filename:<{f_pad}} | {full_hash[:8]}")

        print("=" * width + "\n")

        try:
            orchestration(
                session_jsonl_log_path, final_audit_results_path, test_limit=LIMIT
            )
        finally:
            sys.stdout = original_stdout
            tee.close()
            print(f"\nSession Complete. Log saved to {session_terminal_output}")

        sys.exit(0)
