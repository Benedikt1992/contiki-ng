import logging
import signal

from config import CONFIG
from base_station.logging import setup_logging
from base_station.coap_server import CoAPServer
import threading
import asyncio

from aiocoap import *


logger = logging.getLogger(name='base_station')

control_byte_default = b'\x00'
control_byte_terminate = b'\x02'

revocation_list = []

def MAC_to_payload(mac_addr):
    result = b''
    for group in mac_addr.split('.'):
        result += bytes.fromhex(group)
    return result

def build_payload(control_byte, revoke_node, dst_node_addrs):
    payload = b''
    payload += control_byte
    payload += revoke_node
    payload += bytes([len(dst_node_addrs)])
    for addr in dst_node_addrs:
        payload += addr
    return payload

class BaseStation:

    def __init__(self):
        setup_logging()
        self.aio_loop = asyncio.new_event_loop()
        self._start_server()
        signal.signal(signal.SIGINT, self._stop_server)
        signal.signal(signal.SIGTERM, self._stop_server)

    async def run(self):
        if not CONFIG['on_mote']:

            client = await Context.create_client_context()

            payload = build_payload(
                control_byte_default,
                MAC_to_payload('0200.0000.0000.0000'),
                [MAC_to_payload('0001.0001.0001.0001')]
            )

            request = Message(code=POST, payload=payload)
            request.opt.uri_host = CONFIG['host']
            request.opt.uri_path = tuple(filter(None, CONFIG['path'].split('/')))

            try:
                response = await client.request(request).response
            except Exception as e:
                print('Failed to fetch resource:')
                print(e)
            else:
                print('Result: %s\n%r' % (response.code, response.payload))

    def _start_server(self):
        t = threading.Thread(target=CoAPServer().run, args=(self.aio_loop,), daemon=False, name="CoAP Server")
        t.start()

    def _stop_server(self, *args, **kwargs):
        print("Shutting down. Please wait...")
        self.aio_loop.stop()


if __name__ == '__main__':
    asyncio.get_event_loop().run_until_complete(BaseStation().run())
