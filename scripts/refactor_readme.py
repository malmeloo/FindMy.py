#!/usr/bin/env python3

"""Script to resolve relative URLs in README prior to release."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


def main(args: list[str]) -> int:
    if len(args) < 1:
        print("No README path supplied.")
        return 1

    remote_url = (
        subprocess.run(
            ["/usr/bin/env", "git", "remote", "get-url", "origin"],
            check=True,
            capture_output=True,
        )
        .stdout.decode("utf-8")
        .strip()
    )

    # Convert SSH remote URLs to HTTPS
    remote_url = re.sub(r"^ssh://git@", "https://", remote_url)

    readme_path = Path(args[0])
    readme_content = readme_path.read_text("utf-8")

    new_content = re.sub(
        r"(\[[^]]+]\()((?!https?:)[^)]+)(\))",
        lambda m: m.group(1) + remote_url + "/blob/main/" + m.group(2) + m.group(3),
        readme_content,
    )

    readme_path.write_text(new_content)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
