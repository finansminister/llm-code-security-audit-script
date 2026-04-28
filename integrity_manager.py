import hashlib
import json
import sys
from pathlib import Path


def end_of_process_integrity(final_metadata, start_metadata):
    validate_integrity(
        start_metadata["live_hashes"],
        final_metadata["live_hashes"],
        context="System Source Code:",
        source_code=True,
    )


def llm_output_integrity(manifest_path: Path, output_dir: Path) -> None:

    print(f"Verifying output integrity of: {output_dir}")

    with open(manifest_path, "r") as file:
        original_hashes = json.load(file)

    current_hashes = {}
    for file_path in output_dir.glob("*.py"):
        with open(file_path, "rb") as file:
            current_hash = hashlib.sha256(file.read()).hexdigest()
            current_hashes[file_path.name] = current_hash

    validate_integrity(
        original_hashes, current_hashes, context=f"LLM Output -> {output_dir.name}"
    )
    print(
        f"SUCCESS: All generated files for {output_dir.name} verified as bit-identical."
    )


def validate_integrity(
    baseline_hashes: dict, live_hashes: dict, context: str, source_code: bool = False
) -> None:

    missing = baseline_hashes.keys() - live_hashes.keys()
    added = live_hashes.keys() - baseline_hashes.keys()

    same = baseline_hashes.keys() & live_hashes.keys()
    modified = [file for file in same if baseline_hashes[file] != live_hashes[file]]

    drifts = {"MISSING": missing, "MODIFIED": modified}
    if source_code:
        drifts["UNAUTHORIZED"] = added

    current_drifts = {reason: file for reason, file in drifts.items() if file}
    if current_drifts:
        print(f"CRITICAL INTEGRITY FAILURE: {context}")
        for reason, file in current_drifts.items():
            print(f"-> {reason}: {list(file)}")
        sys.exit(1)


def current_hash_values(source_code_files, master_hashes_path):
    live_hashes = {}
    if not master_hashes_path.exists():
        print(
            "WARNING: No master .json hashes file found. Proceeding without version validation."
        )
        master_hashes = {}
    else:
        with open(master_hashes_path, "r") as file:
            master_hashes = json.load(file)

    frozen_hashes_date = master_hashes.get("date", "unknown")

    for file in source_code_files:
        sha256_hash = hashlib.sha256()
        with open(file, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)

        current_hash = sha256_hash.hexdigest()
        live_hashes[file.name] = current_hash

        if not master_hashes.get(file.name):
            print(
                f"CRITICAL: {file.name} is not tracked in master_hashes.json. Please run freeze_hashes.py."
            )
            sys.exit(1)
        if current_hash != master_hashes[file.name]:
            print(
                f"{file.name} has been modified since {frozen_hashes_date} and does not match up with the master hash file."
            )
            print(
                "Audit aborted due to integrity failure. Reset master hashes or revert changes."
            )
            sys.exit(1)
    return live_hashes, frozen_hashes_date


def current_files(source_code_files):
    authorized_py_files = {path.name for path in source_code_files}
    current_py_files = {file.name for file in Path(".").glob("*.py")}

    unauthorized_files = current_py_files - authorized_py_files
    missing_files = authorized_py_files - current_py_files

    if unauthorized_files:
        print(
            f"CRITICAL: Unauthorized script(s) detected in root: {unauthorized_files}"
        )
        sys.exit(1)

    if missing_files:
        print(f"CRITICAL: Missing source code file(s): {missing_files}")
        sys.exit(1)

    print("Inventory Validation Successful: 0 Unauthorized files, 0 Missing files.")

    return current_py_files


def orchestration_integrity_check(source_code_files: list, master_hashes_path: Path):
    current_py_files = current_files(source_code_files)
    live_hashes, frozen_hashes_date = current_hash_values(
        source_code_files, master_hashes_path
    )
    current_state_metadata = {
        "live_hashes": live_hashes,
        "current_files": frozenset(current_py_files),
        "master_hashes_date": frozen_hashes_date,
    }
    return current_state_metadata
