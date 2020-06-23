import argparse
import logging
import sys
from xml.etree import ElementTree as ET

from modules import parser

PARSER = argparse.ArgumentParser()
PARSER.add_argument('--inputfile', '-if', type=str, required=True, help='Path to input .nessus file')
PARSER.add_argument('--outputfile', '-of', type=str, default='./compliance_results.csv', help='Path to output CSV file')
PARSER.add_argument('--outputdelim', '-od', type=str, default=',', help='Output file delimiter (default: "%(default)s")')
ARGS = PARSER.parse_args()

logging.basicConfig(format='%(message)s', level=logging.INFO, stream=sys.stderr)


def main():
    # define namespaces for non-default elements to stop search breaking
    xml_namespaces = {'cm': 'http://www.nessus.org/cm'}

    logging.info(f"[i] Reading file from: {ARGS.inputfile}")
    try:
        # get document root
        xml_doc = ET.parse(ARGS.inputfile).getroot()

        # iterate through all Report elements within the provided .nessus file
        for report in xml_doc.findall('Report'):
            report_hosts = parser.parse_hosts(report)

            report_issues = list()
            for host in report_hosts:
                logging.info(f"[i] Collecting services for host: {host.get('name')}")
                services = parser.parse_services(host, xml_namespaces)
                logging.info(f"[i] Found {len(services)} service(s)")
                if services:
                    tcp_services = list(filter(lambda x: x.protocol == 'tcp', services))
                    udp_services = list(filter(lambda x: x.protocol == 'udp', services))

                    logging.info(f"\tTCP: {len(tcp_services)}\n\tUDP: {len(udp_services)}")

                # passed_percent = round(len(passed) / len(compliance_issues) * 100, 2) if len(passed) > 0 else 0
                # failed_percent = round(len(failed) / len(compliance_issues) * 100, 2) if len(failed) > 0 else 0

                # # strip out anything with a status of WARNING
                # compliance_issues = list(filter(lambda x: x.result in ['PASSED', 'FAILED'], compliance_issues))
                # logging.info(
                #     f"[i] Found {len(compliance_issues)} compliance issues\n\tPassed: {len(passed)} ({passed_percent}%)\n\tFailed: {len(failed)} ({failed_percent}%)")

                # report_issues = [*report_issues, *compliance_issues]

            # sort issues by name
            # report_issues = sorted(report_issues, key=lambda x: x.name)
            # headers = ['Host', 'Check Name', 'Configured Value', 'Expected Value', 'Info', 'Solution', 'Result']
            # output.write_output(ARGS.outputfile, headers, report_issues, ARGS.outputdelim)
            # logging.info(f"[i] Output file written to: {ARGS.outputfile}")

    except Exception as err:
        logging.error(f"[!] {err}")


if __name__ == '__main__':
    main()
