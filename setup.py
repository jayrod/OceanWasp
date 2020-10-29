# -*- coding: utf-8 -*-


"""setup.py: setuptools control."""


import re
from os.path import exists
from setuptools import setup

if exists("README.md"):
    with open("README.md", "rb") as f:
        long_descr = f.read().decode("utf-8")
else:
    long_descr = "Custom nmap initial enumeration tool",

setup(
    name = "cmdline-OceanWasp",
    packages = ["OceanWasp"],
    entry_points = {
        "console_scripts": ['OceanWasp = OceanWasp.OceanWasp:main']
        },
    install_requires = [
        "markdown-table",
        "python-nmap",
        "rich",
        "tabulate"
    ],
    version = '1.0.5',
    description = "Custom nmap initial enumeration tool",
    long_description = long_descr,
    author = "",
    author_email = "",
    )
