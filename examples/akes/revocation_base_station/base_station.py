import logging
from coapthon.client.helperclient import HelperClient
from config import CONFIG
from base_station.logging import setup_logging


logger = logging.getLogger(name='base_station')

control_byte_default = '\x00'
control_byte_terminate = '\x02'

revocation_list = []

def MAC_to_payload(mac_addr):
    result = ''
    for group in mac_addr.split('.'):
        result += bytes.fromhex(group).decode('utf-8')
    return result

def build_payload(control_byte, revoke_node, dst_node_addrs):
    payload = ''
    payload += control_byte
    payload += revoke_node
    payload += bytes([len(dst_node_addrs)]).decode('utf-8')
    for addr in dst_node_addrs:
        payload += addr
    return payload

class BaseStation:

    def __init__(self):
        setup_logging()

    def run(self):
        if not CONFIG['on_mote']:
            client = HelperClient(server=(CONFIG['host'], CONFIG['port']))

            payload = build_payload(
                control_byte_default,
                MAC_to_payload('0200.0000.0000.0000'),
                [MAC_to_payload('0001.0001.0001.0001')]
            )

            response = client.post(CONFIG['path'], payload, timeout=None)
            print(response.pretty_print())

            payload = build_payload(
                control_byte_default,
                MAC_to_payload('0200.0000.0000.0000'),
                [MAC_to_payload('0300.0000.0000.0000'), MAC_to_payload('0400.0000.0000.0000')]
            )

            response = client.post(CONFIG['path'], payload, timeout=None)
            print(response.pretty_print())


if __name__ == '__main__':
    BaseStation().run()
