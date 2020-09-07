import logging
import re
from xml.etree import ElementTree as ET

from models import service as svc
from models import share as sh
from models import vulnerability as vl


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
    if use_fqdns:
        fqdn = parse_fqdns(report_host)
    else:
        fqdn = None

    detected_services = list(filter(lambda x: x.attrib['pluginName'] == 'Service Detection', report_items))

    for item in detected_services:
        hostname = fqdn or report_host.get('name')
        port = int(item.get('port'))
        service_name = item.get('svc_name')
        protocol = item.get('protocol')
        plugin_output = getattr(item.find('plugin_output'), 'text')

        # http_proxy, www, https? are all web things
        # search for SSL/TLS in plugin_output to know to add https:

        # TODO: come up with a better way to map port/service/proto to a URI
        if port == 80 and protocol == 'tcp' and service_name == 'www':
            uri = 'http://'
        elif protocol == 'tcp' and service_name in ['www', 'https?', 'pcsync-https?']:
            uri = 'https://'
        elif port == 21 and protocol == 'tcp' and service_name == 'ftp':
            uri = 'ftp://'
        elif port == 22 and protocol == 'tcp' and service_name == 'ssh':
            uri = 'ssh://'
        else:
            uri = f"{protocol}://"

        service = svc.Service(hostname, port, service_name, protocol, uri)
        parsed_services.append(service)

    return parsed_services


def parse_shares(report_host: ET.Element, use_fqdns: bool) -> list:
    """
    Extract SMB shares from the supplied ReportHost element

    Arguments:
        report_host {ET.Element} -- ReportHost element extracted from the current Report element
        use_fqdns {bool} --  Flag to extract FQDNs from scan results

    Returns:
        list -- List of SMB shares for the given ReportHost
    """

    if use_fqdns:
        fqdn = parse_fqdns(report_host)
    else:
        fqdn = None

    report_items = report_host.findall('ReportItem')

    parsed_shares = list()
    detected_shares = list(filter(lambda x: x.attrib['pluginName'] == 'Microsoft Windows SMB Shares Enumeration', report_items))

    for item in detected_shares:
        hostname = fqdn or report_host.get('name')
        port = int(item.get('port'))
        service_name = item.get('svc_name')
        protocol = item.get('protocol')
        plugin_output = getattr(item.find('plugin_output'), 'text')

        # parse plugin output to get all shares
        plugin_output = plugin_output.strip().split('\n')
        for line in plugin_output[3:]:  # skip the first 3 elements as they aren't relevant
            share_name = re.search('^\s{2}-\s(.*)', line)[1]
            # share_name = 'AAA'
            uncpath = f"\\\\{hostname}\\{share_name}"
            share = sh.Share(hostname, port, service_name, protocol, uncpath)
            parsed_shares.append(share)

    return parsed_shares


def parse_share_permissions(report_host: ET.Element) -> list:
    """
    Parse share permissions from the supplied ReportHost element

    Args:
        report_host (ET.Element): ReportHost element extracted from the current Report element

    Returns:
        list: List of SMB share permissions for the given ReportHost
    """
    host_properties = report_host.find('HostProperties')
    report_items = report_host.findall('ReportItem')

    parsed_permissions = list()
    all_permissions = list(filter(lambda x: x.attrib['pluginName'] == 'Microsoft Windows SMB Share Permissions Enumeration', report_items))

    for item in all_permissions:
        plugin_output = getattr(item.find('plugin_output'), 'text')
        parsed_permissions.append(plugin_output)

    return parsed_permissions


def parse_vulnerabilities(report_host: ET.Element, minseverity: int, maxseverity: int) -> list:
    """
    Parse vulnerabilities from the supplied ReportHost element

    Args:
        report_host (ET.Element): ReportHost elemenet extracted from teh current Report element
        minseverity (int): Minimum issue severity to include

    Returns:
        list: List of vulnerabilities for the given ReportHost
    """
    host_properties = report_host.find('HostProperties')
    report_items = report_host.findall('ReportItem')

    parsed_vulnerabilities = list()
    all_vulnerabilities = list(filter(lambda x: int(x.get('severity')) >= minseverity and int(x.get('severity')) <= maxseverity, report_items))

    for item in all_vulnerabilities:
        plugin_name = item.get('pluginName')
        plugin_severity = int(item.get('severity'))

        vuln = vl.Vulnerability(plugin_name, plugin_severity)
        parsed_vulnerabilities.append(vuln)

    return parsed_vulnerabilities


def parse_fqdns(report_host: ET.Element) -> str:
    """
    Extract FQDN using a variety of plugins for the supplied ReportHost

    Args:
        report_host (ET.Element): ReportHost element to extract FQDN for

    Returns:
        str: FQDN or IP address if no FQDN exists
    """
    report_items = report_host.findall('ReportItem')
    host_properties = report_host.find('HostProperties')

    # There are multiple methods of finding the hostname, this one seems to work for HTTPS services
    resolved_fqdns = list(filter(lambda x: x.attrib['pluginName'] == 'Host Fully Qualified Domain Name (FQDN) Resolution', report_items))
    if resolved_fqdns:
        # TODO: handle cases where multiple hostnames exist
        for item in resolved_fqdns:
            plugin_output = getattr(item.find('plugin_output'), 'text')
            fqdn = re.search('((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}', plugin_output)[0]

    else:
        host_fqdn = getattr(host_properties.find('tag[@name="host-fqdn"]'), 'text', '')
        if host_fqdn:
            fqdn = host_fqdn
        else:
            hostname = getattr(host_properties.find('tag[@name="netbios-name"]'), 'text', '')
            domain = getattr(host_properties.find('tag[@name="wmi-domain"]'), 'text', '')

            if hostname and domain:
                fqdn = f"{hostname}.{domain}"
            else:
                fqdn = getattr(host_properties.find('tag[@name="host-ip"]'), 'text')
    return fqdn
