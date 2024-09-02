#!/usr/bin/env python3

import json
from itertools import count
from pathlib import Path
from typing import Generator

import tomli
from packaging.specifiers import SpecifierSet
from packaging.version import Version


def get_python_versions() -> Generator[str, None, None]:
    """Get all python versions this package is compatible with."""
    with Path("pyproject.toml").open("rb") as f:
        pyproject_data = tomli.load(f)

    specifier = SpecifierSet(pyproject_data["tool"]["poetry"]["dependencies"]["python"])

    below_spec = True
    for v_minor in count():
        version = Version(f"3.{v_minor}")

        # in specifier: yield
        if version in specifier:
            below_spec = False
            yield str(version)
            continue

        # below specifier: skip
        if below_spec:
            continue

        # above specifier: return
        return


print(json.dumps(list(get_python_versions())))
