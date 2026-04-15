import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

TERRAVIEW_PROVIDER = os.getenv("TERRAVIEW_PROVIDER", "anthropic")
DEFAULT_MODEL = os.getenv("TERRAVIEW_MODEL", "claude-sonnet-4-6")
MAX_TOKENS = int(os.getenv("TERRAVIEW_MAX_TOKENS", "8192"))
LOG_LEVEL = os.getenv("TERRAVIEW_LOG_LEVEL", "INFO")
SENTINEL_BASE_URL = os.getenv("TERRAVIEW_BASE_URL", "")

# Keep SENTINEL_PROVIDER as fallback for anyone using old env var name
SENTINEL_PROVIDER = TERRAVIEW_PROVIDER

SUPPORTED_MODELS = [
    "claude-sonnet-4-6",
    "claude-opus-4-6",
    "claude-haiku-4-5-20251001",
    "gpt-4o",
    "gpt-4o-mini",
]

PROJECT_ROOT = Path(__file__).parent.parent.parent
EXAMPLES_DIR = PROJECT_ROOT / "examples"
