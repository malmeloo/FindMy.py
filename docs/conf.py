"""Configuration file for the Sphinx documentation builder."""
# ruff: noqa: A001
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information
import os
import re

project = "FindMy.py"
copyright = "2024, Mike Almeloo"
author = "Mike Almeloo"
version = re.sub("^v", "", os.popen("git describe --tags").read().strip())  # noqa: S605, S607
release = version

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "myst_parser",
    "sphinx.ext.duration",
    "sphinx.ext.autodoc",
    "sphinx.ext.inheritance_diagram",
    "autoapi.extension",
]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# -- AutoAPI Options ---------------------------------------------------------
autoapi_dirs = ["../findmy/"]
autoapi_root = "reference/"
autoapi_add_toctree_entry = False
autoapi_keep_files = True
autoapi_options = [
    "members",
    "undoc-members",
    "show-inheritance",
    "show-inheritance-diagram",
    "show-module-summary",
    "special-members",
    "imported-members",
]

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "sphinx_book_theme"
html_static_path = ["_static"]
