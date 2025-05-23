"""usage: python -m findmy"""  # noqa: D400, D415

import argparse
import logging
from importlib.metadata import version
from pathlib import Path

from .plist import decrypt_all


def main() -> None:  # noqa: D103
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(prog="findmy", description="FindMy.py CLI tool")
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=version("FindMy"),
    )
    subparsers = parser.add_subparsers(dest="command", title="commands")
    subparsers.required = True

    decrypt_parser = subparsers.add_parser(
        "decrypt",
        help="Decrypt all the local FindMy accessories to JSON files.",
    )
    decrypt_parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("accessories/"),
        help="Output directory for decrypted files (default: accessories/)",
    )

    args = parser.parse_args()
    if args.command == "decrypt":
        for acc in decrypt_all(out_dir=args.out_dir):
            print(f"Decrypted accessory: {acc.name} ({acc.identifier})")  # noqa: T201
    else:
        # This else block should ideally not be reached if subparsers.required is True
        # and a default command isn't set, or if a command is always given.
        # However, it's good practice for unexpected cases or if the logic changes.
        parser.print_help()
        parser.exit(1)


if __name__ == "__main__":
    main()
