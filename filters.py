import json
from pathlib import Path

FILTERS_FILE = "filters.json"

def load_filters():
    if Path(FILTERS_FILE).exists():
        try:
            with open(FILTERS_FILE, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}
    return {}

def save_filters(filters):
    with open(FILTERS_FILE, "w") as f:
        json.dump(filters, f, indent=2)
