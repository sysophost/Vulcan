import logging
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


def parse_services(report_host: ET.Element, ns: dict) -> list:
    """
    Extract compliance issues from the supplied ReportHost element

    Arguments:
        report_host {ET.Element} -- ReportHost element extracted from the current Report element
        ns {dict} -- Node namespace aliases

    Returns:
        list -- List of compliance issue objects for the given ReportHost
    """

    host_properties = report_host.find('HostProperties')
    report_items = report_host.findall('ReportItem')

    services = list()

    for ri in report_items:
        if ri.attrib['pluginName'] == 'Service Detection':
            hostname = report_host.get('name')
            port = ri.get('port')
            service_name = ri.get('svc_name')
            protocol = ri.get('protocol')
            plugin_output = ri.get('plugin_output')

            # TODO: map URI prefix based on svc_name
            # TODO: identify TCP and UDP services separately

            # http_proxy, www, https? are all web things
            # www is http
            # search for SSL/TLS in plugin_output to know to add https:

            uri = ''

            service = s.Service(hostname, port, service_name, protocol, uri)
            services.append(service)

    return services
