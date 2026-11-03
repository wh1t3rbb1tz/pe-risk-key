# SPDX-License-Identifier: AGPL-3.0-or-later
"""Serve the dashboard API (localhost only unless explicitly allowed)."""

import argparse
import os
import sys

import uvicorn


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)
    if (
        args.host != "127.0.0.1"
        and os.getenv("PE_RISK_KEY_ALLOW_REMOTE") != "1"
    ):
        print(
            f"Refusing to bind to {args.host}: PE Risk Key serves "
            "localhost only. Set PE_RISK_KEY_ALLOW_REMOTE=1 to override.",
            file=sys.stderr,
        )
        raise SystemExit(2)
    if not os.getenv("MODEL_API_KEY"):
        print(
            "Warning: MODEL_API_KEY is not set; new runs will fail. "
            "Add it to .env (see .env.example).",
            file=sys.stderr,
        )
    uvicorn.run(
        "pe_risk_key.api.app:app",
        host=args.host,
        port=args.port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
