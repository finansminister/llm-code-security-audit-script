import json
import random
import re
import time
from pathlib import Path
from typing import Optional

import requests
from bs4 import BeautifulSoup

from config import OWASP2025


def owasp_scrape(a_code: str, url: str, max_retries: int) -> Optional[str]:
    for attempt in range(max_retries):
        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            return response.text
        except (
            requests.exceptions.RequestException,
            requests.exceptions.Timeout,
        ):
            if attempt < max_retries:
                delay = (2**attempt) + random.uniform(0, 1)
                time.sleep(delay)
            else:
                print(
                    f"Critical Failure: Failed to retrieve {a_code} after {max_retries} attempts..."
                )
    return None


def generate_cwe_dict() -> dict:
    cwe_dict = {}
    max_retries = 3
    for a_code, url in OWASP2025.URLS.items():
        response = owasp_scrape(a_code, url, max_retries)
        if not response:
            continue

        soup = BeautifulSoup(response, "html.parser")

        h2 = soup.find("h2", id="list-of-mapped-cwes")
        if not h2:
            continue

        for list_item in h2.find_next_siblings():
            # check for new section
            if list_item.name in ["h2", "h3"]:
                break
            for a_tag in list_item.find_all("a"):
                cwe = re.search(r"cwe-(\d+)", a_tag.text, re.IGNORECASE)
                if cwe:
                    # Standardizing CWE Codes:
                    # cwe-22 -> cwe-022
                    # group(0) = cwe-123
                    # group(1) = 123
                    cwe_id = f"cwe-{int(cwe.group(1)):03d}"
                    cwe_dict[cwe_id] = a_code

    return cwe_dict


def load_owasp_dict(cwe_dict_file: Path) -> dict:
    try:
        with open(cwe_dict_file, "r", encoding="utf-8") as file:
            cwe_dict = json.load(file)

        print(f"Using cached OWASP 2025 CWE map: {cwe_dict_file.name}")
        return cwe_dict

    except (FileNotFoundError, json.JSONDecodeError):
        print(
            f"{cwe_dict_file.name} not found. Generating new OWASP 2025 CWE dictionary..."
        )
        cwe_dict = generate_cwe_dict()

        with open(cwe_dict_file, "w", encoding="utf-8") as file:
            json.dump(cwe_dict, file, indent=4, sort_keys=True)
        return cwe_dict
