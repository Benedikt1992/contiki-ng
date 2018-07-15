from coapthon.server.coap import CoAP
from base_station.coap_resources.akes_revoke import AkesRevokeResource
from config import CONFIG

class CoAPServer(CoAP):
    def __init__(self, host, port):
        CoAP.__init__(self, (host, port))
        self.add_resource(CONFIG['path'], AkesRevokeResource())