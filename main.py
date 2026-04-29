import shutil
import sys
import time

from dotenv import load_dotenv

from audit_manager import Tee
from codeql_manager import codeql_and_parse
from config import Directories, LLMConfig
from generation_manager import code_generation_pipeline

# In main.py
from integrity_manager import (
    end_of_process_integrity,
    generate_hashes,
    llm_output_integrity,
)
from llm_api_manager import (
    anthropic_api_call,
    gemini_api_call,
    get_clients,
    mistral_api_call,
)
from owasp_manager import cwe_per_owasp, load_owasp_dict
from statistics_manager import run_statistics


def environment_setup():

    start_hashes_metadata = generate_hashes()

    if shutil.which("codeql") is None:
        print("CRITICAL ERROR: CodeQL CLI not found in System PATH.")
        print("Please install CodeQL or update your PATH variable.")
        sys.exit(1)

    load_dotenv()
    Directories.directories_check()
    return (LLMConfig.get_api_parameters(), get_clients(), start_hashes_metadata)


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
