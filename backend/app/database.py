from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB_PATH = PROJECT_ROOT / "backend" / "agenttrace.db"
DEFAULT_REPORT_DIR = PROJECT_ROOT / "reports"


def ensure_parent_dir(path: Path) -> Path:
    """Create parent directories for a path when they do not already exist."""
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def ensure_directory(path: Path) -> Path:
    """Create a directory and return it."""
    path.mkdir(parents=True, exist_ok=True)
    return path
