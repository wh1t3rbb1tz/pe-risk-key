"""Download the CISA KEV catalog once to data/kev_snapshot.json.

US government public data; the snapshot is fine to commit. Re-run to
refresh (the file records its own snapshot_date).
"""

import json
from datetime import date
from pathlib import Path
from urllib.request import urlopen

KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT_PATH = ROOT / "data" / "kev_snapshot.json"


def main() -> None:
    with urlopen(KEV_FEED_URL, timeout=30) as response:
        catalog = json.load(response)
    snapshot = {
        "snapshot_source": KEV_FEED_URL,
        "snapshot_date": date.today().isoformat(),
        **catalog,
    }
    SNAPSHOT_PATH.parent.mkdir(parents=True, exist_ok=True)
    SNAPSHOT_PATH.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    count = len(catalog.get("vulnerabilities", []))
    print(f"wrote {SNAPSHOT_PATH} ({count} entries, {SNAPSHOT_PATH.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
