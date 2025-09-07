from __future__ import annotations

from pathlib import Path

from findmy import FindMyAccessory


def main(output: Path, accessory_plist: Path, alignment_plist: Path | None = None) -> int:
    accessory = FindMyAccessory.from_plist(accessory_plist, alignment_plist)
    accessory.to_json(output)
    return 0


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser()
    parser.add_argument("accessory_plist", type=Path, help="Input accessory plist file")
    parser.add_argument("output", type=Path, help="Output JSON file")
    parser.add_argument(
        "--alignment-plist",
        type=Path,
        help="Input alignment plist file (if available)",
        default=None,
    )
    args = parser.parse_args()

    sys.exit(main(args.output, args.accessory_plist, args.alignment_plist))
