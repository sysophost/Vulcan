class Service(object):
    def __init__(self, hostname, port, service_name, protocol, uri):
        self.hostname = hostname
        self.port = port
        self.service_name = service_name
        self.protocol = protocol
        self.uri = uri
