import logging

from config import CONFIG

def setup_logging():
    '''
    This function will setup the logger facility of python to write log files for every micro service, storage provider
    and the logerator itself.
    '''

    output_format = '[%(levelname)-8s] [%(name)-15s] %(message)s'

    logging.basicConfig(format=output_format, level=CONFIG['log_level'])

