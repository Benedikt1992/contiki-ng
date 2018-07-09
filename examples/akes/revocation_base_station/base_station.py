import logging
import json
from coapthon.client.helperclient import HelperClient
from config import CONFIG
from base_station.logging import setup_logging


logger = logging.getLogger(name='base_station')


class BaseStation:

    def __init__(self):
        setup_logging()

    def run(self):
        if not CONFIG['on_mote']:
            client = HelperClient(server=(CONFIG['host'], CONFIG['port']))
            response = client.post(CONFIG['path'], '4', timeout=None)

            print( response.pretty_print())
            client.stop()


if __name__ == '__main__':
    BaseStation().run()

