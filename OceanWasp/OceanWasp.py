# -*- coding: utf-8 -*-

"""OceanWasp.OceanWasp: provides entry point main()."""

__version__ = "0.1.0dev"

import sys
import argparse
from pathlib import Path
from typing import Tuple
from ipaddress import ip_address

from tabulate import tabulate 

from OceanWasp.top1kports import PORTS

try:
    from nmap import PortScanner
    from markdown_table import Table
except ImportError:
    print("pip install dependencies")
    sys.exit()

def msg(message: str) -> str:
    return "[+] {0}".format(message)

def err_msg(message: str) -> str:
    return "[!] {0}".format(message)

def validate_input(args) -> ip_address:
    #determine if the input IP address is inface an IP
    try:
        ip = ip_address(args.target_host)    
    except ValueError:
        print(err_msg("Argument was not a valid IP address"))
        sys.exit()

    #Input check file 
    if args.output:
        if Path(args.output).is_dir():
            print(err_msg("Given argument is a path and not a file"))
            sys.exit()

    return ip

def create_md_table(scanner : PortScanner) -> Tuple[list, list]:
    columns = ["Host", "Port", "Service Name", "Product", "Version", "Extra Info", "Platform Enumeration"]
    full_table = []

    for scanned_host in scanner.all_hosts():
        if 'tcp' in scanner[scanned_host].keys():
            for port, info in scanner[scanned_host]['tcp'].items():
                if info['state'] == 'open':
                    serv_name = info['name']
                    serv_prod = info['product']
                    serv_ver = info['version']
                    serv_extra = info['extrainfo']
                    serv_cpe = info['cpe']

                    full_table.append([scanned_host, str(port), serv_name, serv_prod, serv_ver, serv_extra, serv_cpe])

    return columns, full_table

def render_md_table(columns: list, full_table: list) -> str:
    return Table(columns, full_table).render()


def render_tab_table(columns: list, full_table: list) -> str:
    return tabulate(full_table, headers=columns, tablefmt="fancy_grid")

def main():
    print("Executing OceanWasp version %s." % __version__)

    parser = argparse.ArgumentParser()
    parser.add_argument("target_host", help="IP address for target.")
    parser.add_argument("-o", "--output", help="File to append data.")
    args = parser.parse_args()

    ip = validate_input(args)
    
    scan_ports = PORTS
    scanner = PortScanner()

    print(msg("Performing scan of target {0}".format(str(ip))))
    scanner.scan(str(ip), ",".join(scan_ports))

    #Do not continue if the host was not up
    if scanner.scanstats()['uphosts'] == '0':
        print(err_msg("Target host {0} does not appear to be up".format(str(ip))))
        sys.exit()

    #create column and output data
    columns, table = create_md_table(scanner)

    #if Output file given then write output to it
    if args.output:
        md_table = render_md_table(columns, table)

        with open(args.output, "a+") as output_file:
            output_file.write("\n")
            output_file.write(md_table)

    print(msg("Scan Results"))
    tabulate_table = render_tab_table(columns, table)

    print(tabulate_table)
