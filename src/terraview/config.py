import os
from dotenv import load_dotenv

load_dotenv()

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

TERRAVIEW_PROVIDER = os.getenv("TERRAVIEW_PROVIDER", "anthropic")
DEFAULT_MODEL = os.getenv("TERRAVIEW_MODEL", "claude-sonnet-4-6")
MAX_TOKENS = int(os.getenv("TERRAVIEW_MAX_TOKENS", "8192"))
LOG_LEVEL = os.getenv("TERRAVIEW_LOG_LEVEL", "INFO")
BASE_URL = os.getenv("TERRAVIEW_BASE_URL", "")

SUPPORTED_PROVIDERS = ["anthropic", "openai", "ollama"]
