"""usage: python -m findmy"""  # noqa: D400, D415

from __future__ import annotations

import argparse
import json
import logging
from importlib.metadata import version
from pathlib import Path

from .plist import get_key, list_accessories


def main() -> None:  # noqa: D103
    parser = argparse.ArgumentParser(prog="findmy", description="FindMy.py CLI tool")
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=version("FindMy"),
    )
    parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Set the logging level (default: INFO)",
    )
    subparsers = parser.add_subparsers(dest="command", title="commands")
    subparsers.required = True

    decrypt_parser = subparsers.add_parser(
        "decrypt",
        help="Decrypt all the local FindMy accessories to JSON. This will print the JSON to stdout.",  # noqa: E501
    )
    decrypt_parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Output directory for decrypted files. If not specified, files will not be saved to disk.",  # noqa: E501
    )

    args = parser.parse_args()
    logging.basicConfig(level=args.log_level.upper())
    if args.command == "decrypt":
        decrypt_all(args.out_dir)
    else:
        # This else block should ideally not be reached if subparsers.required is True
        # and a default command isn't set, or if a command is always given.
        # However, it's good practice for unexpected cases or if the logic changes.
        parser.print_help()
        parser.exit(1)


def decrypt_all(out_dir: str | Path | None = None) -> None:
    """Decrypt all accessories and save them to the specified directory as JSON files."""

    def get_path(d, acc) -> Path | None:  # noqa: ANN001
        if out_dir is None:
            return None
        d = Path(d)
        d = d.resolve().absolute()
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{acc.identifier}.json"

    key = get_key()
    accs = list_accessories(key=key)
    jsons = [acc.to_json(get_path(out_dir, acc)) for acc in accs]
    print(json.dumps(jsons, indent=2, ensure_ascii=False))  # noqa: T201


if __name__ == "__main__":
    main()
