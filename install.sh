#!/bin/bash
pip3 uninstall OceanWasp
python3 setup.py develop
pip3 install -e . --force-reinstall
