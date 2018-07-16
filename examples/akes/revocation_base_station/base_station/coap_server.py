from base_station.coap_resources.akes_revoke import AkesRevokeResource
from config import CONFIG
import asyncio

import aiocoap.resource as resource
import aiocoap

class CoAPServer:
    def __init__(self):
        # Resource tree creation
        self.root = resource.Site()

        self.root.add_resource(('.well-known', 'core'), resource.WKCResource(self.root.get_resources_as_linkheader))
        self.root.add_resource(tuple(filter(None, CONFIG['path'].split('/'))), AkesRevokeResource())

    def run(self, loop):
        asyncio.set_event_loop(loop)
        asyncio.Task(aiocoap.Context.create_server_context(self.root))
        loop.run_forever()
