import logging

from config import CONFIG

def setup_logging():
    '''
    This function will setup the logger facility of python to write log files for every micro service, storage provider
    and the logerator itself.
    '''

    output_format = '[%(asctime)s] [%(levelname)-8s] [%(name)-20s] %(message)s'
    date_format = "%Y-%m-%d %H:%M:%S"
    if CONFIG['log_to_file']:
        logging.basicConfig(format=output_format,
                            level=logging.ERROR,
                            datefmt=date_format,
                            filename='base_station.log',
                            filemode='w')
    else:
        logging.basicConfig(format=output_format,
                            level=logging.ERROR,
                            datefmt=date_format
                            )
    logging.getLogger('base_station').setLevel(CONFIG['log_level'])
