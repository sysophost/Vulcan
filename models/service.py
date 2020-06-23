class Service(object):
    def __init__(self, hostname: str, port: int, service_name: str, protocol: str, uri: str):
        self.hostname = hostname
        self.port = port
        self.service_name = service_name
        self.protocol = protocol
        self.uri = uri
