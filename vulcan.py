import argparse
import asyncio
import logging
import os
import sys
from xml.etree import ElementTree as ET

import pyppeteer

from modules import parser
from modules.pyShot import pyShot

PARSER = argparse.ArgumentParser()
PARSER.add_argument('--inputfile', '-if', type=str, required=True, help='Path to input .nessus file')
PARSER.add_argument('--services', '-sv', action='store_true', help='Extract all services identified by the Service Detection plugin')
PARSER.add_argument('--urls', '-u', action='store_true', help='Only print things with http:// or https:// URI')
PARSER.add_argument('--screenshot', '-s', action='store_true', help='Capture screenshots of any http:// or https:// URI')
PARSER.add_argument('--proxy', '-p', type=str, help='Proxy to use for capturing screenshots e.g. http://127.0.0.1:8080')
PARSER.add_argument('--outputdir', '-od', type=str, help='Path to output directory for screenshots')
PARSER.add_argument('--shares', '-sh', action='store_true', help='Extract SMB shares')
PARSER.add_argument('--sharepermissions', '-sp', action='store_true', help='Extract SMB share permissions')
PARSER.add_argument('--listvulnerabilities', '-lv', action='store_true', help='List vulnerabilities by host')
PARSER.add_argument('--listallvulnerabilities', '-lva', action='store_true', help='List unique vulnerabilities')
PARSER.add_argument('--minseverity', '-ns', type=int, default=1, choices=[0, 1, 2, 3, 4], help='Filter by minimum severity 0=Info, 4=Critical')
PARSER.add_argument('--maxseverity', '-xs', type=int, default=5, choices=[0, 1, 2, 3, 4], help='Filter by maximum severity 0=Info, 4=Critical')
PARSER.add_argument('--fqdns', '-f', action='store_true', help='Include resolved FQDN')
PARSER.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')

ARGS = PARSER.parse_args()

if ARGS.verbose:
    logging.basicConfig(format='%(message)s', level=logging.DEBUG, stream=sys.stderr)
else:
    logging.basicConfig(format='%(message)s', level=logging.INFO, stream=sys.stderr)

# Suppress pyppeteer logs
pyppeteer_logger = logging.getLogger('pyppeteer')
pyppeteer_logger.setLevel(logging.WARNING)


async def capture(s: pyShot, browser: pyppeteer.browser, services: list):
    coros = [s.capture_screenshot(browser, f"{service.uri}{service.hostname}:{service.port}") for service in services]
    await asyncio.gather(*coros)
    await browser.close()


def screenshot_urls(proxy, outputdir, urls):
    s = pyShot.pyShot(proxy, outputdir)
    loop = asyncio.get_event_loop()
    browser = loop.run_until_complete(s.get_browser())

    if outputdir:
        try:
            if not os.path.isdir(outputdir):
                os.mkdir(outputdir)
        except Exception:
            logging.error(f'[!] Something failed when creating the folder {outputdir}')
            sys.exit(1)

    loop.run_until_complete(capture(s, browser, urls))


def main():
    logging.info(f"[i] Reading file from: {ARGS.inputfile}")
    try:
        # get document root
        xml_doc = ET.parse(ARGS.inputfile).getroot()
        vulnerability_list = list()

        # iterate through all Report elements within the provided .nessus file
        for report in xml_doc.findall('Report'):
            report_hosts = parser.parse_hosts(report)

            report_issues = list()
            for host in report_hosts:
                if ARGS.fqdns:
                    fqdn = parser.parse_fqdns(host)
                else:
                    fqdn = None

                hostname = fqdn or host.get('name')

                if ARGS.services or ARGS.urls:
                    logging.debug(f"[i] Collecting services for host: {hostname}")
                    services = parser.parse_services(host, ARGS.fqdns)
                    if services:
                        tcp_services = list(filter(lambda x: x.protocol == 'tcp', services))
                        udp_services = list(filter(lambda x: x.protocol == 'udp', services))
                        logging.debug(f"[i] Found {len(tcp_services)} TCP and {len(udp_services)} UDP services")

                        services = sorted(set(services), key=lambda x: x.uri)
                        for service in services:
                            if (ARGS.urls and service.uri in ['http://', 'https://']) or not ARGS.urls:
                                print(f"{service.uri}{service.hostname}:{service.port}")

                        if ARGS.screenshot:
                            http_services = list(filter(lambda s: s.uri in ['http://', 'https://'], services))
                            screenshot_urls(ARGS.proxy, ARGS.outputdir, http_services)
                    else:
                        logging.debug(f"[x] No services found")

                if ARGS.shares:
                    logging.debug(f"[i] Collecting shares for host: {hostname}")
                    shares = parser.parse_shares(host, ARGS.fqdns)
                    if shares:
                        logging.debug(f"[i] Found {len(shares)} share(s)")
                        shares = sorted(set(shares), key=lambda x: x.uncpath)
                        for share in shares:
                            print(f"{share.uncpath}")
                    else:
                        logging.debug(f"[x] No shares found")

                if ARGS.sharepermissions:
                    logging.debug(f"[i] Collecting share permissions for host: {hostname}")
                    share_permissions = parser.parse_share_permissions(host)
                    if share_permissions:
                        logging.debug(f"[i] Found permissions for share(s)")
                        for permission in share_permissions:
                            print(f"{permission}")
                    else:
                        logging.debug(f"[x] No share permissions found")

                if ARGS.listvulnerabilities or ARGS.listallvulnerabilities:
                    logging.debug(f"[i] Collecting vulnerabilities for host: {hostname}")
                    vulnerabilities = parser.parse_vulnerabilities(host, ARGS.minseverity, ARGS.maxseverity)

                    if vulnerabilities:
                        logging.debug(f"[i] Found {len(vulnerabilities)} vulnerabilities")
                        vuln_list = sorted(set(vulnerabilities), key=lambda x: x.severity, reverse=True)
                        for vuln in vuln_list:
                            vulnerability_list.append(vuln)
                            if ARGS.listvulnerabilities:
                                print(f"{hostname}\t{vuln.severity_name}\t{vuln.name}")
                    else:
                        logging.debug(f"[x] No vulnerabilities found")

        if ARGS.listallvulnerabilities:
            vulnerability_list = sorted({v.name: v for v in vulnerability_list}.values(), key=lambda x: x.severity, reverse=True)
            for vulnerability in vulnerability_list:
                print(f"{vulnerability.severity_name} - {vulnerability.name}")

    except Exception as err:
        logging.error(f"[!] {err}")


if __name__ == '__main__':
    main()
