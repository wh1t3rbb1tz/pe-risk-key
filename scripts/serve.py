"""Serve the dashboard API on 127.0.0.1:8000 (localhost only)."""

import uvicorn


def main() -> None:
    uvicorn.run(
        "pe_risk_key.api.app:app", host="127.0.0.1", port=8000, log_level="info"
    )


if __name__ == "__main__":
    main()
