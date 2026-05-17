import contextlib
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Optional

from dotenv import load_dotenv
from rich.align import Align
from rich.panel import Panel
from wakepy import keep

from config import Directories, LLMConfig, Styles, UIConfig
from config import Telemetry as t
from src.analysis import Tee, run_statistics
from src.core import (
    end_of_process_integrity,
    generate_hashes,
    llm_output_integrity,
    sarif_parser,
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

S: Any = Styles


def environment_setup() -> tuple:

    start_hashes_metadata = generate_hashes()

    if shutil.which("codeql") is None:
        print("CRITICAL ERROR: CodeQL CLI not found in System PATH.")
        print("Please install CodeQL or update your PATH variable.")
        sys.exit(1)

    Directories.initialize_session_tree()
    return (LLMConfig.get_api_parameters(), get_clients(), start_hashes_metadata)


def resume_session(session_log_dir: Path) -> Optional[str]:
    sessions = sorted(
        [dir for dir in session_log_dir.iterdir() if dir.is_dir()],
        key=lambda x: x.stat().st_mtime,
        reverse=True,
    )

    if not sessions:
        return None
    session_list = "\n".join(
        [f"[{S.INFO}][{i}][/] {session.name}" for i, session in enumerate(sessions, 1)]
    )
    t.print(
        Panel(
            session_list,
            title=f"[{S.INFO}]Recent Audit Sessions",
            subtitle=f"[{S.SUBTITLE}]Select an index to resume or leave blank for new",
            expand=False,
            padding=(1, 4),
        )
    )
    choice = input(
        "\nResume a previous session? (Enter session index [#] or leave blank for new session): "
    ).strip()
    if choice.isdigit() and 1 <= int(choice) <= len(sessions):
        return sessions[int(choice) - 1].name
    return None


def orchestration(
    session_jsonl_log_path: Path, final_audit_results_path: Path, test_limit=None
) -> None:
    api_parameters, client, start_hashes_metadata = environment_setup()
    cwe_dict = load_owasp_dict(Directories.OWASP_MAP_PATH)
    cwe_per_owasp(cwe_dict, "OWASP_2025_Mapping", session_jsonl_log_path.parent)
    # Api Call Functions
    api_call_funcs = {
        "meta": meta_api_call,
        "gemini": gemini_api_call,
        "anthropic": anthropic_api_call,
        "mistral": mistral_api_call,
    }

    model_configs = LLMConfig.model_cfg(client, api_call_funcs)

    stats = []
    for loop_index, model in enumerate(model_configs, start=1):
        t.rule("INFO", f"MODEL {loop_index}/{len(model_configs)}: {model['id']}")
        sarif_path = Directories.RESULTS_DIR / f"{model['name']}_analysis_report.sarif"
        if sarif_path.exists():
            t.log(
                "INFO",
                "Skipping CodeQL: Report already exists for {}",
                target=model["name"],
            )
            results = sarif_parser(sarif_path, cwe_dict, model["name"])
            if results:
                stats.extend(results)
            continue

        output_manifest = code_generation_pipeline(
            model, api_parameters, session_jsonl_log_path, test_limit=test_limit
        )

        if output_manifest is None:
            t.log(
                "ERROR",
                f"Pipeline failed for {model['id']}. Skipping analysis.",
                error=RuntimeError("Manifest empty"),
            )
            continue

        llm_output_integrity(output_manifest, model["output_dir"])
        results, report_path = codeql_and_parse(
            model["name"], model["output_dir"], cwe_dict
        )
        if results:
            stats.extend(results)

        panel_content = (
            f"Vulnerability Report Generated: [{S.FILE}]{report_path.name}[/]\n"
            f"Integrity Check: [{S.PASSED}]PASSED[/]"
        )
        t.center_panel(
            panel_content,
            f"Completion: {model['name']}",
            status="SUCCESS",
            subtitle=f"[{S.SUBTITLE}]{model['id']}[/]",
        )

    t.rule("SUCCESS", "ALL MODELS PROCESSED")

    t.print(f"\n[{S.FILE}]Final System State Validation[/]")

    final_hashes_metadata = generate_hashes()
    end_of_process_integrity(final_hashes_metadata, start_hashes_metadata)

    if stats:
        run_statistics(stats, final_audit_results_path)


def terminal_output(TEST_MODE: bool, LIMIT=None):
    tee = Tee(session_terminal_output)
    original_stdout = sys.stdout
    original_stderr = sys.stderr
    sys.stdout = tee
    sys.stderr = tee
    t.rule("INFO", f"{'TEST RUN ACTIVE' if TEST_MODE else 'FULL AUDIT START'}")
    t.print(f"Sample Size: {LIMIT if TEST_MODE else '121'} prompts per model")

    if Directories.MASTER_HASH_PATH.exists():
        with open(Directories.MASTER_HASH_PATH, "r") as file:
            master = json.load(file)

        baseline_info = [
            f"[{S.INFO}]Baseline Date:[/] {master.get('date', 'Unknown')}\n"
        ]
        for filename, full_hash in master.items():
            if filename != "date":
                baseline_info.append(
                    f"[{S.FILE}]{filename:<{f_pad}}[/] | [white]{full_hash[:24]}[/]"
                )
        baseline_panel = Panel(
            "\n".join(baseline_info),
            title=f"[{S.INFO}]Master Integrity Baseline",
            border_style=f"{S.INFO}",
            padding=(1, 2),
        )

        centered_content = Align.center(baseline_panel, width=UIConfig.WIDTH)
        t.print(centered_content)
    try:
        orchestration(
            session_jsonl_log_path, final_audit_results_path, test_limit=LIMIT
        )
    finally:
        t.log(
            "INFO",
            "Session Complete. Log saved to",
            file_path=session_terminal_output,
        )
        sys.stdout = original_stdout
        sys.stderr = original_stderr
        t.console.file = sys.stdout  # Reset Rich console
        tee.close()


if __name__ == "__main__":
    TEST_MODE = False
    LIMIT = 5 if TEST_MODE else None

    load_dotenv()
    Directories.directories_check_root()

    if (legacy_session_id := resume_session(Directories.PARENT_OUTPUT_DIR)) is not None:
        Directories.rebase_session(legacy_session_id)

    session_log_dir = Directories.OUTPUT_DIR / "session-logs"
    session_log_dir.mkdir(parents=True, exist_ok=True)
    session_jsonl_log_path = session_log_dir / "code_generation_log.jsonl"
    final_audit_results_path = (
        Directories.RESULTS_DIR / f"final_audit_results_{Directories.SESSION_ID}.csv"
    )
    session_terminal_output = session_log_dir / "session_terminal_output.txt"

    width = UIConfig.WIDTH
    f_pad = UIConfig.FILE_PATH_TRUNCATE
    with contextlib.redirect_stderr(open(os.devnull, "w")):
        try:
            if not (wakelock := keep.running()):
                wakelock = contextlib.nullcontext()
        except Exception:
            wakelock = contextlib.nullcontext()

        with wakelock:
            terminal_output(TEST_MODE, LIMIT)
            sys.exit(0)
