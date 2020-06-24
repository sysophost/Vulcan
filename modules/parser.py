import logging
import re
from xml.etree import ElementTree as ET

from models import service as s


def parse_hosts(report: ET.Element) -> list:
    """
    Extract hosts from the supplied Report element

    Arguments:
        report {ET.Element} -- Report element extracted from the document root

    Returns:
        list -- List of hosts extracted from the supplied Report element
    """

    logging.info(f"[i] Parsing report: {report.get('name')}")
    report_hosts = report.findall('./ReportHost')
    return report_hosts


def parse_services(report_host: ET.Element, use_fqdns: bool) -> list:
    """
    Extract identified services from the supplied ReportHost element

    Arguments:
        report_host {ET.Element} -- ReportHost element extracted from the current Report element
        use_fqdns {bool} --  Flag to extract FQDNs from scan results

    Returns:
        list -- List of services for the given ReportHost
    """

    # TODO: come up with a way to collect and report services that are not identified by the Service Detection plugin (basically just open ports)

    host_properties = report_host.find('HostProperties')
    report_items = report_host.findall('ReportItem')

    parsed_services = list()
    fqdn = None

    fqdns = list(filter(lambda x: x.attrib['pluginName'] == 'Host Fully Qualified Domain Name (FQDN) Resolution', report_items))
    detected_services = list(filter(lambda x: x.attrib['pluginName'] == 'Service Detection', report_items))

    if len(fqdns) > 1:
        print("Found multiple hostnames")
        # TODO: If multiple host entries are matched, insert both?
        # Maybe add a way to highlight the fact its multiple hostnames for the same box?

    for item in fqdns:
        plugin_output = getattr(item.find('plugin_output'), 'text')
        fqdn = re.search('((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}', plugin_output)[0]
        logging.debug(f"[i] Found FQDN: {fqdn}")

    for item in detected_services:
        if use_fqdns and fqdn:
            hostname = fqdn
        else:
            hostname = report_host.get('name')
        port = int(item.get('port'))
        service_name = item.get('svc_name')
        protocol = item.get('protocol')
        plugin_output = getattr(item.find('plugin_output'), 'text')

        # http_proxy, www, https? are all web things
        # search for SSL/TLS in plugin_output to know to add https:

        # TODO: come up with a better way to map port/service/proto to a URI
        if port == 80 and protocol == 'tcp' and service_name == 'www':
            uri = 'http://'
        elif port in [443, 8443] and protocol == 'tcp' and service_name in ['www', 'https?', 'pcsync-https?']:
            uri = 'https://'
        elif port == 21 and protocol == 'tcp' and service_name == 'ftp':
            uri = 'ftp://'
        elif port == 22 and protocol == 'tcp' and service_name == 'ssh':
            uri = 'ssh://'
        else:
            uri = f"{protocol}://"

        service = s.Service(hostname, port, service_name, protocol, uri)
        parsed_services.append(service)

    return parsed_services
