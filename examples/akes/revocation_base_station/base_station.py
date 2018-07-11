import logging
import json
from coapthon.client.helperclient import HelperClient
from config import CONFIG
from base_station.logging import setup_logging


logger = logging.getLogger(name='base_station')

control_byte_default = '\x00'
control_byte_terminate = '\x02'

revocation_list = []

def MAC_to_bytearray(mac_addr):
    result = ''
    for group in mac_addr.split('.'):
        result += bytes.fromhex(group).decode('utf-8')
    return result

def build_payload(control_byte, revoke_node, dst_node_addrs):
    payload = ''
    payload += control_byte
    payload += revoke_node
    for addr in dst_node_addrs:
        payload += addr
    return payload

class BaseStation:

    def __init__(self):
        setup_logging()

    def run(self):
        if not CONFIG['on_mote']:
            client = HelperClient(server=(CONFIG['host'], CONFIG['port']))

            payload = build_payload(control_byte_default,
                                    MAC_to_bytearray('0200.0000.0000.0000'),
                                    [MAC_to_bytearray('0100.0000.0000.0000')]
                                   )
            print(payload)
            #payload.decode('ascii')
            response = client.post(CONFIG['path'], payload, timeout=None)

            print( response.pretty_print())


if __name__ == '__main__':
    BaseStation().run()

