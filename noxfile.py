"""Configuration file for Nox."""

from itertools import count
from pathlib import Path
from typing import Generator

import nox
import tomllib
from packaging.specifiers import SpecifierSet
from packaging.version import Version


def get_python_versions() -> Generator[str, None, None]:
    """Get all python versions this package is compatible with."""
    with Path("pyproject.toml").open("rb") as f:
        pyproject_data = tomllib.load(f)

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


@nox.session(python=list(get_python_versions()))
def test(session: nox.Session) -> None:
    """Run unit tests."""
    session.run("pytest")
