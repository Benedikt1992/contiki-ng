'''
See README.md for the meaning of every key.
'''
import logging

CONFIG = {
    "on_mote": False,
    "log_to_file": False,
    "cooja_malicious_node_id": 2,
    "log_level": logging.DEBUG,
    "path": "akes/revoke",
    "initial_network": [
        '0001.0001.0001.0001',
        '0200.0000.0000.0000',
        '0300.0000.0000.0000',
        '0400.0000.0000.0000',
        '0500.0000.0000.0000'
    ],
    "border_router": [
        ('0001.0001.0001.0001', "fd00::201:1:1:1")
    ]
}
