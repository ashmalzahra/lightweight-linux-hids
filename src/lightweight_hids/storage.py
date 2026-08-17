"""JSON Lines storage for normalized events and alerts."""

import json
from pathlib import Path
from typing import Any

from lightweight_hids.models import Alert, Event


class JsonlStore:
    """Append Events or Alerts to a JSON Lines file."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def append(self, item: Event | Alert) -> None:
        """Append one serialized Event or Alert."""
        self.path.parent.mkdir(parents=True, exist_ok=True)

        with self.path.open("a", encoding="utf-8") as file:
            json.dump(item.to_dict(), file, sort_keys=True)
            file.write("\n")

    def read_all(self) -> list[dict[str, Any]]:
        """Read every non-empty JSON record."""
        if not self.path.exists():
            return []

        records: list[dict[str, Any]] = []

        with self.path.open("r", encoding="utf-8") as file:
            for line in file:
                if line.strip():
                    records.append(json.loads(line))

        return records