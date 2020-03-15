# -*- coding: utf-8 -*-

"""OceanWasp.OceanWasp: provides entry point main()."""

__version__ = "0.4"

import re
import argparse
import sys
from ipaddress import ip_address
from os import environ
from pathlib import Path
from typing import Tuple

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
    # determine if the input IP address is inface an IP
    ip = None

    try:
        # if no target host given
        if not args.target:
            # look for RHOST environ var
            if "RHOST" in environ.keys():
                print(msg("Using Environment variable for IP address"))
                ip = ip_address(environ["RHOST"])
        else:
            ip = ip_address(args.target)

    except ValueError:
        print(err_msg("Argument or environment variable was not a valid IP address"))
        sys.exit()

    # Input check file
    if args.markdown:
        if Path(args.markdown).is_dir():
            print(err_msg("Given argument is a path and not a file"))
            sys.exit()

    return ip


def scanner_to_table(scanner: PortScanner) -> Tuple[list, list, list]:
    columns = [
        "Host",
        "Port",
        "Service Name",
        "Product",
        "Version",
        "Extra Info",
        "Platform Enumeration",
    ]
    full_table = []

    all_hosts = []

    for scanned_host in scanner.all_hosts():
        data = dict()
        data["host"] = scanned_host

        if "tcp" in scanner[scanned_host].keys():
            # add space for open ports information
            data["open_ports"] = list()

            for port, info in scanner[scanned_host]["tcp"].items():
                if info["state"] == "open":
                    port_info = dict()

                    serv_name = info["name"]
                    serv_prod = info["product"]
                    serv_ver = info["version"]
                    serv_extra = info["extrainfo"]
                    serv_cpe = info["cpe"]

                    # create table
                    full_table.append(
                        [
                            scanned_host,
                            str(port),
                            serv_name,
                            serv_prod,
                            serv_ver,
                            serv_extra,
                            serv_cpe,
                        ]
                    )

                    # create dictionairy
                    port_info = {
                        "Port": port,
                        "Service Name": serv_name,
                        "Product": serv_prod,
                        "Version": serv_ver,
                        "Extra Info": serv_extra,
                        "Platform Enumeration": serv_cpe,
                    }
                    data["open_ports"].append(port_info)

        all_hosts.append(data)

    return columns, full_table, all_hosts


def render_md_table(columns: list, full_table: list) -> str:
    return Table(columns, full_table).render()


def render_tab_table(columns: list, full_table: list) -> str:
    return tabulate(full_table, headers=columns, tablefmt="fancy_grid")


def render_text_info(data: list) -> str:
    output_string = ""

    for item in data:
        output_string += "Host : {0}\n".format(item["host"])
        output_string += "\nOpen Ports\n"

        for port_info in item["open_ports"]:
            output_string += "\tPort : {0}\n".format(port_info["Port"])
            output_string += "\tService Name: {0}\n".format(port_info["Service Name"])
            output_string += "\tProduct : {0}\n".format(port_info["Product"])
            output_string += "\tVersion : {0}\n".format(port_info["Version"])
            output_string += "\tExtra Info : {0}\n".format(port_info["Extra Info"])
            output_string += "\tPlatform Enumeration : {0}\n".format(
                port_info["Platform Enumeration"]
            )

    return output_string

def insert_md_table(markdown: str, md_table: str) -> None:
    content = open(markdown, "r").read(-1)

    # regex
    regex = r"\[\[\s?OceanWasp\s?\]\]"

    # if there exists a tag then substitute our data into it
    if re.findall(regex, content, re.IGNORECASE):
        content = re.sub(regex, md_table, content, re.IGNORECASE)
    else:
        content += md_table

    with open(markdown, "w") as m_file:
        m_file.write(content)


def main():
    print("Executing OceanWasp version %s." % __version__)

    parser = argparse.ArgumentParser()
    parser.add_argument("--target", help="IP address for target.")
    parser.add_argument("--markdown", help="Markdown File to append data.")
    parser.add_argument("--text", help="Text File to append data.")
    args = parser.parse_args()

    ip = validate_input(args)

    if not ip:
        print(err_msg("Check IP argument"))
        sys.exit(-1)

    scan_ports = PORTS
    scanner = PortScanner()

    print(msg("Performing scan of target {0}".format(str(ip))))
    scanner.scan(str(ip), ",".join(scan_ports))

    # Do not continue if the host was not up
    if scanner.scanstats()["uphosts"] == "0":
        print(err_msg("Target host {0} does not appear to be up".format(str(ip))))
        sys.exit()

    # create column and output data
    columns, table, data_dict = scanner_to_table(scanner)

    # if Output file given then write output to it
    if args.markdown:
        print(msg("Writing markdown to file"))
        md_table = render_md_table(columns, table)

        #insert md table into document
        insert_md_table(args.markdown, md_table)

    # if text argument given then output to text file
    if args.text:
        print(msg("Writing scan results to text file"))
        text = render_text_info(data_dict)

        #if folder doesn't exist then create it
        if not Path(args.text).parent.exists():
            Path(args.text).parent.mkdir(parents=True)

        with open(args.text, "a+") as text_file:
            text_file.write("\n")
            text_file.write(text)

    print(msg("Scan Results"))
    tabulate_table = render_tab_table(columns, table)

    print(tabulate_table)
