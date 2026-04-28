import hashlib
import json
import time

from config import SourceCode


def freeze_current_hashes():
    source_code_files = SourceCode.source_code_check()

    master_hashes = {"date": time.strftime("%Y-%m-%d %H:%M:%S")}

    for file in source_code_files:
        sha256_hash = hashlib.sha256()

        with open(file, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        master_hashes[file.name] = sha256_hash.hexdigest()

    with open("master_hashes.json", "w") as file:
        json.dump(master_hashes, file, indent=4)

    print("Hashes frozen in master_hashes.json")


if __name__ == "__main__":
    freeze_current_hashes()
