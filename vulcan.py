import argparse
import logging
import sys
from xml.etree import ElementTree as ET

from modules import parser

PARSER = argparse.ArgumentParser()
PARSER.add_argument('--inputfile', '-if', type=str, required=True, help='Path to input .nessus file')
PARSER.add_argument('--urls', '-u', action='store_true', help='Only print things with http:// or https:// URI')
PARSER.add_argument('--shares', '-s', action='store_true', help='Extract SMB shares')
PARSER.add_argument('--fqdns', '-f', action='store_true', help='Include resolved FQDN')
PARSER.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')

ARGS = PARSER.parse_args()

if ARGS.verbose:
    logging.basicConfig(format='%(message)s', level=logging.DEBUG, stream=sys.stderr)
else:
    logging.basicConfig(format='%(message)s', level=logging.INFO, stream=sys.stderr)


def main():
    logging.info(f"[i] Reading file from: {ARGS.inputfile}")
    try:
        # get document root
        xml_doc = ET.parse(ARGS.inputfile).getroot()
        service_uris = list()
        share_list = list()
        # iterate through all Report elements within the provided .nessus file
        for report in xml_doc.findall('Report'):
            report_hosts = parser.parse_hosts(report)

            report_issues = list()
            for host in report_hosts:
                logging.debug(f"[i] Collecting services for host: {host.get('name')}")
                services = parser.parse_services(host, ARGS.fqdns)
                if services:
                    tcp_services = list(filter(lambda x: x.protocol == 'tcp', services))
                    udp_services = list(filter(lambda x: x.protocol == 'udp', services))
                    logging.debug(f"\tFound {len(tcp_services)} TCP and {len(udp_services)} UDP services")

                    for service in services:
                        if (ARGS.urls and service.uri in ['http://', 'https://']) or not ARGS.urls:
                            service_uris.append(service)
                else:
                    logging.debug(f"\tNo services found")

                if ARGS.shares:
                    logging.debug(f"[i] Collecting shares for host: {host.get('name')}")
                    shares = parser.parse_shares(host, ARGS.fqdns)
                    if shares:
                        logging.debug(f"\tFound {len(shares)} share(s)")
                        for share in shares:
                            share_list.append(share)

        service_uris = sorted(set(service_uris), key=lambda x: x.uri)
        for service in service_uris:
            print((f"{service.uri}{service.hostname}:{service.port}"))

        share_list = sorted(set(share_list), key=lambda x: x.uncpath)
        for share in share_list:
            print((f"{share.uncpath}"))

    except Exception as err:
        logging.error(f"[!] {err}")


if __name__ == '__main__':
    main()
