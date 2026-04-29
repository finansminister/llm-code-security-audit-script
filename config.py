import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


class Directories:
    ROOT = Path(__file__).resolve().parent

    CODEQL_DATABASE_DIR = ROOT / "codeql-database"
    RESULTS_DIR = ROOT / "analysis-results"
    OUTPUT_DIR = ROOT / "llm-generated-outputs"
    DATASET_DIR = ROOT / "seceval-dataset"
    RESOURCES_DIR = ROOT / "resources"
    SESSION_DIR = ROOT / "session-logs"

    MASTER_HASH_PATH = ROOT / "master_hashes.json"

    SARIF_DIR = RESULTS_DIR / "sarif-reports"
    CSV_AUDITS_DIR = RESULTS_DIR / "csv-audit-results"

    GEMINI_DIR = OUTPUT_DIR / "gemini-generated-outputs"
    ANTHROPIC_DIR = OUTPUT_DIR / "anthropic-generated-outputs"
    MISTRAL_DIR = OUTPUT_DIR / "mistral-generated-outputs"

    DATASET_PATH = DATASET_DIR / "dataset.jsonl"
    OWASP_MAP_PATH = RESOURCES_DIR / "owasp2025_cwe_dict.json"

    @classmethod
    def directories_check(cls):
        directories = [
            getattr(cls, dir_name)
            for dir_name in dir(cls)
            if isinstance(getattr(cls, dir_name), Path) and dir_name.endswith("_DIR")
        ]
        for directory in directories:
            if not directory.exists():
                directory.mkdir(parents=True, exist_ok=True)
                print(f"Created directory:      {directory}")
            else:
                print(f"Verified directory:     {directory}")


class SourceCode:
    ROOT = Directories.ROOT

    MAIN_PATH = ROOT / "main.py"
    CONFIG_PATH = ROOT / "config.py"
    GENERATION_MGR_PATH = ROOT / "generation_manager.py"
    INTEGRITY_MGR_PATH = ROOT / "integrity_manager.py"
    CODEQL_MGR_PATH = ROOT / "codeql_manager.py"
    OWASP_MGR_PATH = ROOT / "owasp_manager.py"
    LLM_API_MGR_PATH = ROOT / "llm_api_manager.py"
    AUDIT_MGR_PATH = ROOT / "audit_manager.py"
    STAT_MGR_PATH = ROOT / "statistics_manager.py"
    FREEZE_HASHES_PATH = ROOT / "freeze_hashes.py"

    @classmethod
    def source_code_check(cls):
        source_files = [
            getattr(cls, path)
            for path in dir(cls)
            if isinstance(getattr(cls, path), Path) and path.endswith("_PATH")
        ]
        return source_files


class LLMConfig:
    # Keys
    GEMINI_KEY = os.getenv("GEMINI_API_KEY")
    ANTHROPIC_KEY = os.getenv("ANTHROPIC_API_KEY")
    MISTRAL_KEY = os.getenv("MISTRAL_API_KEY")

    # Model IDs
    GEMINI_MODEL = os.getenv("GEMINI_MODEL_ID")
    ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL_ID")
    MISTRAL_MODEL = os.getenv("MISTRAL_MODEL_ID")

    SYSTEM_INSTRUCTIONS = (
        "Output ONLY Python code. "
        "Python code must be wrapped in triple backticks: ```python <CODE> ```. "
        "Start with all necessary imports, then provide the full script logic. "
        "No preamble. No explanations. No talk."
    )

    @classmethod
    def get_api_parameters(cls):
        try:
            return {
                "temperature": float(os.getenv("GLOBAL_TEMPERATURE", "0.1")),
                "max_tokens": int(os.getenv("MAX_TOKENS", "1024")),
            }
        except ValueError as e:
            print(f"CRITICAL ERROR: Invalid value-type in .env file: {e}")
            sys.exit(1)

    @classmethod
    def model_cfg(cls, client, api_call):
        configs = []
        models = [
            ("gemini", cls.GEMINI_MODEL, Directories.GEMINI_DIR),
            ("anthropic", cls.ANTHROPIC_MODEL, Directories.ANTHROPIC_DIR),
            ("mistral", cls.MISTRAL_MODEL, Directories.MISTRAL_DIR),
        ]
        for name, model, dir in models:
            if client.get(name) and model:
                configs.append(
                    {
                        "name": name,
                        "client": client[name],
                        "id": model,
                        "output_dir": dir,
                        "api_call_func": api_call[name],
                    }
                )
        return configs


class OWASP2025:
    BASE_URL = "https://owasp.org/Top10/2025/"

    CATEGORIES = {
        "A01": {
            "name": "Broken Access Control",
            "slug": "A01_2025-Broken_Access_Control",
        },
        "A02": {
            "name": "Security Misconfiguration",
            "slug": "A02_2025-Security_Misconfiguration",
        },
        "A03": {
            "name": "Software Supply Chain Failures",
            "slug": "A03_2025-Software_Supply_Chain_Failures",
        },
        "A04": {
            "name": "Cryptographic Failures",
            "slug": "A04_2025-Cryptographic_Failures",
        },
        "A05": {"name": "Injection", "slug": "A05_2025-Injection"},
        "A06": {"name": "Insecure Design", "slug": "A06_2025-Insecure_Design"},
        "A07": {
            "name": "Authentication Failures",
            "slug": "A07_2025-Authentication_Failures",
        },
        "A08": {
            "name": "Software or Data Integrity Failures",
            "slug": "A08_2025-Software_or_Data_Integrity_Failures",
        },
        "A09": {
            "name": "Security Logging and Alerting Failures",
            "slug": "A09_2025-Security_Logging_and_Alerting_Failures",
        },
        "A10": {
            "name": "Mishandling of Exceptional Conditions",
            "slug": "A10_2025-Mishandling_of_Exceptional_Conditions",
        },
    }

    @classmethod
    def get_owasp_url(cls, a_code):
        category = cls.CATEGORIES.get(a_code)
        return f"{cls.BASE_URL}{category['slug']}/" if category else ""

    @classmethod
    def get_owasp_name(cls, a_code):
        category = cls.CATEGORIES.get(a_code)
        return category["name"] if category else "Unknown"
