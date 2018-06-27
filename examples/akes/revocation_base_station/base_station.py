import logging
import json

from config import CONFIG
from base_station.logging import setup_logging


logger = logging.getLogger(name='base_station')


class BaseStation:

    def __init__(self):
        setup_logging()

    def run(self):
        if not CONFIG['on_mote']:
            logger.debug("Generate static json string.")
            data = [1, 'hallo']
            print(json.dumps(data))


if __name__ == '__main__':
    BaseStation().run()

