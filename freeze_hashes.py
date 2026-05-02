import hashlib
import json
import time
from pathlib import Path
from typing import Optional

from config import SourceCode


def generate_sha256(file_path: Path) -> Optional[str]:
    if not file_path.exists():
        print(f"WARNING: File not found for hashing: {file_path}")
        return None
    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as file:
        for byte_block in iter(lambda: file.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def generate_master_hashes():
    source_code_files = SourceCode.source_code_check()

    master_hashes = {"date": time.strftime("%Y-%m-%d %H:%M:%S")}

    for file_path in source_code_files:
        if (file_hash := generate_sha256(file_path)) is not None:
            relative_path = file_path.relative_to(SourceCode.ROOT)
            master_hashes[str(relative_path)] = file_hash
            print(f"Hashed: {relative_path}")

    output_path = SourceCode.ROOT / "master_hashes.json"
    with open(output_path, "w") as file:
        json.dump(master_hashes, file, indent=4)

    print(f"Hashes frozen in {output_path}")


if __name__ == "__main__":
    generate_master_hashes()
