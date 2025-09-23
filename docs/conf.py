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
    "sphinx_togglebutton",
    "sphinx_design",
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
html_logo = "../assets/icon.png"
html_title = "FindMy.py"
html_copy_source = True
html_favicon = html_logo
html_last_updated_fmt = ""
html_theme_options = {
    "path_to_docs": "docs",
    "repository_url": "https://github.com/malmeloo/FindMy.py",
    "repository_branch": "main",
    "use_edit_page_button": True,
    "use_source_button": True,
    "use_issues_button": True,
    "use_repository_button": True,
    "use_download_button": True,
    "use_sidenotes": True,
    "show_toc_level": 2,
    "logo": {
        "image_dark": html_logo,
        "text": html_title,
    },
    "icon_links": [
        {
            "name": "GitHub",
            "url": "https://github.com/malmeloo/FindMy.py",
            "icon": "fa-brands fa-github",
        },
        {
            "name": "Discord",
            "url": "https://discord.gg/EF6UCG2TF6",
            "icon": "fa-brands fa-discord",
        },
        {
            "name": "PyPI",
            "url": "https://pypi.org/project/FindMy/",
            "icon": "https://img.shields.io/pypi/dw/findmy",
            "type": "url",
        },
    ],
}
