"""Legacy filters module preserved for backward compatibility."""

import json
from pathlib import Path

FILTERS_FILE = "filters.json"


def load_filters():
    if Path(FILTERS_FILE).exists():
        try:
            with open(FILTERS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}
    return {}


def save_filters(filters):
    with open(FILTERS_FILE, "w", encoding="utf-8") as f:
        json.dump(filters, f, indent=2)
