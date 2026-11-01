"""Load only Guardian's trusted configuration, never a scanned project's .env."""
from pathlib import Path
from dotenv import load_dotenv


def load_environment():
    load_dotenv(Path(__file__).resolve().parents[2] / '.env', override=False)
