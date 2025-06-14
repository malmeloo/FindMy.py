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
        help="""
        Decrypt and print (in json) all the local FindMy accessories.

        This looks through the local FindMy accessory plist files,
        decrypts them using the system keychain, and prints the
        decrypted JSON representation of each accessory.

        eg
        ```
        [
            {
                "master_key": "e01ae426431867e92d512ae1cb6c9e5bbc20a2b7d1c677d7",
                "skn": "e01ae426431867e92d512ae1cb6c9e5bbc20a2b7d1c677d7",
                "sks": "e01ae426431867e92d512ae1cb6c9e5bbc20a2b7d1c677d7",
                "paired_at": "2020-01-08T21:26:36.177409+00:00",
                "name": "Nick's MacBook Pro",
                "model": "MacBookPro11,5",
                "identifier": "03FF9E28-2508-425B-BD57-D738F2D2F6C0"
            },
            {
                "master_key": "e01ae426431867e92d512ae1cb6c9e5bbc20a2b7d1c677d7",
                "skn": "e01ae426431867e92d512ae1cb6c9e5bbc20a2b7d1c677d7",
                "sks": "e01ae426431867e92d512ae1cb6c9e5bbc20a2b7d1c677d7",
                "paired_at": "2023-10-22T20:40:39.285225+00:00",
                "name": "ncmbp",
                "model": "MacBookPro18,2",
                "identifier": "71D276DF-A8FA-47C8-A93C-9B3B714BDFEC"
            }
        ]
        ```

        You can chain the output with jq or similar tools.
        eg `python -m findmy decrypt | jq '.[] | select(.name == "my airtag")' > my_airtag.json`
        """,
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
    print(json.dumps(jsons, indent=4, ensure_ascii=False))  # noqa: T201


if __name__ == "__main__":
    main()
