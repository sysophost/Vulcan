class Share(object):
    def __init__(self, hostname: int, port: int, service_name: str, protocol: str, uncpath: str):
        self.hostname = hostname
        self.port = port
        self.service_name = service_name
        self.protocol = protocol
        self.uncpath = uncpath
