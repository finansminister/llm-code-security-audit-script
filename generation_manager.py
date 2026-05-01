import hashlib
import json
import random
import re
import time
from pathlib import Path
from typing import Any, Callable, Optional

from alive_progress import alive_bar

from audit_manager import log_attempt, sanitize_code
from config import Directories


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
    model: dict, api_parameters: dict, log_file_name: Path, test_limit=None
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

        if test_limit:
            random.seed(42)  # Deterministic shuffle for consistency across models
            random.shuffle(prompts)
            prompts = prompts[:test_limit]
            print(f"!!! TEST MODE: Limited to {test_limit} random prompts !!!")
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
