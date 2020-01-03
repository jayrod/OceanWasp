# -*- coding: utf-8 -*-


"""setup.py: setuptools control."""


import re
from os.path import exists
from setuptools import setup


version = re.search(
    '^__version__\s*=\s*"(.*)"',
    open('OceanWasp/OceanWasp.py').read(),
    re.M
    ).group(1)

if exists("README.rst"):
    with open("README.rst", "rb") as f:
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
        "tabulate"
    ],
    version = version,
    description = "Custom nmap initial enumeration tool",
    long_description = long_descr,
    author = "",
    author_email = "",
    )
