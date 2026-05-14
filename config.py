import os
import sys
import time
from pathlib import Path
from typing import Any, Optional

from dotenv import load_dotenv
from rich.align import Align
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel

load_dotenv()


class UIConfig:
    WIDTH = 140
    STATUS_PAD = 15
    ERR_MSG_TRUNCATE = 60
    FILE_PATH_TRUNCATE = 65
    PROGRESS_BAR_WIDTH = 40
    MODEL_ID_TRUNCATE = 25
    PROGRESS_LABEL_PAD = 35

    # STYLE SHEET FOR STATUS UPDATES
    # rich module style colors and font weight
    STATUS_STYLES = {
        "SUCCESS": "bold green",
        "ERROR": "bold red",
        "EMPTY": "bold yellow",
        "REFUSAL": "bold magenta",
        "RETRY": "bold orange3",
        "INFO": "bold cyan",
        "FILE": "cyan",
        "ALREADY_EXISTS": "dim bold green",
        "SUBTITLE": "dim white",
        "PASSED": "green",
        "SIGNIFICANT": "bold sky_blue3",
        "INSIGNIFICANT": "italic dim white",
        "MISC_DATA": "italic white",
    }


class Styles:
    pass


for key, value in UIConfig.STATUS_STYLES.items():
    setattr(Styles, key, value)


class Telemetry:
    # rich.progress console variable used for prints and status updates
    console = Console(
        width=UIConfig.WIDTH,  # Sets a fixed character width for consistent UI across different terminals
        highlight=False,  # Disables automatic regex-based colorization of numbers/strings for cleaner logs
        log_path=False,  # Removes the 'config.py:line' suffix from logs to reduce visual clutter
        force_terminal=True,  # Ensures Rich renders colors and styles even when output is piped to a file (Tee)
        soft_wrap=True,  # Prevents word-wrapping from breaking the structure of long logs or code blocks
    )

    # internal function to calculate style colors with UIConfig.STATUS_STYLES list of colours for rich module
    @classmethod
    def _style(cls, status: str):
        return UIConfig.STATUS_STYLES.get(status, "white")

    @classmethod
    def log(
        cls,
        status: str,
        message: str,
        error: Optional[BaseException] = None,
        file_path: Optional[Path] = None,
        target: Any = None,
        target_type: Optional[str] = None,
    ):

        # the content of the message ignores brackets as to not adjust the color of the log
        # without escape = Error [429]: Too many requests -> Error : Too many requests
        # with escape = Error [429]: Too many requests -> Error [429]: Too many requests
        validated_msg = escape(message)
        target_style = cls._style(target_type) if target_type else cls._style("FILE")
        options = {
            "error": {
                "active": error is not None,
                # We replace {} with () to prevent the string from being
                # treated as a format specifier by the final f-string
                "content": f"{validated_msg} | Error: {str(error).replace('{', '(').replace('}', ')').replace(chr(10), ' ').strip()[: UIConfig.ERR_MSG_TRUNCATE]}",
            },
            "file_path": {
                "active": file_path is not None,
                "content": f"{validated_msg} [{cls._style('FILE')}]{file_path.name if file_path else ''}[/]",
            },
            "target": {
                "active": target is not None,
                "content": (
                    validated_msg.replace(
                        "{}", f"[{cls._style('FILE')}]{escape(str(target))}[/]"
                    )
                    if "{}" in validated_msg
                    else f"{validated_msg} [{target_style}]{escape(str(target))}[/]"
                ),
            },
        }
        final_message = validated_msg
        for key in options.keys():
            if options[key]["active"]:
                final_message = options[key]["content"]
                break

        cls.console.log(
            f"[{cls._style(status)}]{status:<{UIConfig.STATUS_PAD}}[/] | {final_message}"
        )

    @classmethod
    def print(cls, *args, **kwargs):
        cls.console.print(*args, **kwargs)

    @classmethod
    def rule(cls, rule_type: str, title: str = "", **kwargs):
        cls.console.rule(
            f"[{cls._style(rule_type)}]{title}", style=cls._style(rule_type), **kwargs
        )

    @classmethod
    def status(cls, status_type: str, content: str, spinner: str = "dots"):
        return cls.console.status(
            f"[{cls._style(status_type)}]{content}", spinner=spinner
        )

    @classmethod
    def center_panel(
        cls,
        panel_content: str,
        title: str,
        status: str = "SUCCESS",
        subtitle: str = "",
    ):

        final_panel = Panel(
            panel_content,
            title=f"{title}",
            style=UIConfig.STATUS_STYLES.get(status, "white"),
            border_style=UIConfig.STATUS_STYLES.get(status, "white"),
            subtitle=subtitle if subtitle != "" else "",
            expand=False,
            padding=(1, 2),
        )

        centered_output = Align.center(final_panel, width=UIConfig.WIDTH)

        cls.console.print("\n")
        cls.console.print(centered_output)


class Directories:
    ROOT = Path(__file__).resolve().parent
    SESSION_ID = time.strftime("%Y%m%d_%H%M%S")
    SESSION_ID_READABLE = time.strftime("%Y-%m-%d %H:%M:%S")

    CODEQL_DATABASE_DIR = ROOT / "codeql-databases"
    PARENT_OUTPUT_DIR = ROOT / "llm-generated-outputs"
    DATASET_DIR = ROOT / "seceval-dataset"
    RESOURCES_DIR = ROOT / "resources"

    OUTPUT_DIR = PARENT_OUTPUT_DIR / f"code-audit-{SESSION_ID}"
    RESULTS_DIR = OUTPUT_DIR / "analysis-results"

    GEMINI_DIR = OUTPUT_DIR / "gemini-generated-outputs"
    ANTHROPIC_DIR = OUTPUT_DIR / "anthropic-generated-outputs"
    MISTRAL_DIR = OUTPUT_DIR / "mistral-generated-outputs"
    META_DIR = OUTPUT_DIR / "meta-generated-outputs"

    MASTER_HASH_PATH = ROOT / "master_hashes.json"
    DATASET_PATH = DATASET_DIR / "dataset.jsonl"
    OWASP_MAP_PATH = RESOURCES_DIR / "owasp2025_cwe_dict.json"

    @classmethod
    def rebase_session(cls, old_session_id: str):

        cls.SESSION_ID = old_session_id
        try:
            date_obj = time.strptime(old_session_id, "%Y%m%d_%H%M%S")
            cls.SESSION_ID_READABLE = time.strftime("%Y-%m-%d %H:%M:%S", date_obj)
        except ValueError:
            cls.SESSION_ID_READABLE = old_session_id

        clean_id = old_session_id.replace("code-audit-", "")

        cls.OUTPUT_DIR = cls.PARENT_OUTPUT_DIR / f"code-audit-{clean_id}"
        cls.RESULTS_DIR = cls.OUTPUT_DIR / "analysis-results"

        cls.GEMINI_DIR = cls.OUTPUT_DIR / "gemini-generated-outputs"
        cls.ANTHROPIC_DIR = cls.OUTPUT_DIR / "anthropic-generated-outputs"
        cls.MISTRAL_DIR = cls.OUTPUT_DIR / "mistral-generated-outputs"
        cls.META_DIR = cls.OUTPUT_DIR / "meta-generated-outputs"

    @classmethod
    def _directory_verification(cls, rule_text: str, root_only: bool = False):
        Telemetry.rule("INFO", rule_text)
        all_directories = [
            getattr(cls, d)
            for d in dir(cls)
            if isinstance(getattr(cls, d), Path) and d.endswith("_DIR")
        ]

        directories_to_verify = [
            d for d in all_directories if (d.parent == cls.ROOT) == root_only
        ]

        for directory in directories_to_verify:
            rel_path = directory.relative_to(cls.ROOT)
            if not directory.exists():
                directory.mkdir(parents=True, exist_ok=True)
                Telemetry.log("SUCCESS", "Created directory:  ./", file_path=rel_path)
            else:
                Telemetry.log(
                    "ALREADY_EXISTS", "Verified directory: ./", file_path=rel_path
                )

    @classmethod
    def directories_check_root(cls):
        cls._directory_verification("Environment Root Directory Check", root_only=True)

    @classmethod
    def initialize_session_tree(cls):
        cls._directory_verification("Initializing Session Tree")


class SourceCode:
    ROOT = Directories.ROOT
    SRC = ROOT / "src"

    ANALYSIS_DIR = SRC / "analysis"
    CORE_DIR = SRC / "core"
    LLM_DIR = SRC / "llm"
    SCANNERS_DIR = SRC / "scanners"

    MAIN_PATH = ROOT / "main.py"
    CONFIG_PATH = ROOT / "config.py"
    FREEZE_HASHES_PATH = ROOT / "freeze_hashes.py"

    INTEGRITY_MGR_PATH = CORE_DIR / "integrity.py"
    PARSER_MGR_PATH = CORE_DIR / "parser.py"

    GENERATION_MGR_PATH = LLM_DIR / "generator.py"
    LLM_API_MGR_PATH = LLM_DIR / "clients.py"

    CODEQL_MGR_PATH = SCANNERS_DIR / "codeql.py"
    OWASP_MGR_PATH = SCANNERS_DIR / "owasp.py"

    AUDIT_MGR_PATH = ANALYSIS_DIR / "audit.py"
    STAT_MGR_PATH = ANALYSIS_DIR / "stats.py"

    @classmethod
    def source_code_check(cls):
        source_files = [
            getattr(cls, path)
            for path in dir(cls)
            if isinstance(getattr(cls, path), Path) and path.endswith("_PATH")
        ]
        init_files = list(cls.SRC.glob("**/__init__.py"))

        return source_files + init_files


class LLMConfig:
    # Keys
    META_KEY = os.getenv("META_API_KEY")
    GEMINI_KEY = os.getenv("GEMINI_API_KEY")
    ANTHROPIC_KEY = os.getenv("ANTHROPIC_API_KEY")
    MISTRAL_KEY = os.getenv("MISTRAL_API_KEY")

    # Model IDs
    META_MODEL = os.getenv("OPENROUTER_META_MODEL_ID")
    MISTRAL_MODEL = os.getenv("OPENROUTER_MISTRAL_MODEL_ID")
    GEMINI_MODEL = os.getenv("GEMINI_MODEL_ID")
    ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL_ID")

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
                "max_tokens": int(os.getenv("MAX_TOKENS", "4096")),
            }
        except ValueError as e:
            Telemetry.log("ERROR", "Invalid value-type in .env file", error=e)
            sys.exit(1)

    @classmethod
    def model_cfg(cls, client, api_call):
        configs = []
        models = [
            ("meta", cls.META_MODEL, Directories.META_DIR),
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
