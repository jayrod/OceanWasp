# -*- coding: utf-8 -*-

"""OceanWasp.OceanWasp: provides entry point main()."""

__version__ = "0.1.0dev"

import sys
import argparse
from ipaddress import ip_address
from pathlib import Path

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
    if Path(args.output).is_dir():
        print(err_msg("Given argument is a path and not a file"))
        sys.exit()

    return ip

def create_info_table(scanner : PortScanner) -> str:
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

    return Table(columns, full_table).render()


def main():
    print("Executing OceanWasp version %s." % __version__)

    parser = argparse.ArgumentParser()
    parser.add_argument("target_host", help="IP address for target.")
    parser.add_argument("output", help="File to append data.")
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

    md_table = create_info_table(scanner)

    with open(args.output, "a+") as output_file:
        output_file.write(md_table)

        
