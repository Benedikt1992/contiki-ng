'''
See README.md for the meaning of every key.
'''
import logging

CONFIG = {
    "on_mote": False,
    "log_to_file": True,
    "log_level": logging.DEBUG,
    "path": "akes/revoke",
    "max_destinations": 2,
    "ll_address_size": 8,

# 25 nodes 2 borders
    "initial_network": [
        '0001.0001.0001.0001',
        '0200.0000.0000.0000',
        '0300.0000.0000.0000',
        '0400.0000.0000.0000',
        '0500.0000.0000.0000',
        '0600.0000.0000.0000',
        '0c00.0000.0000.0000',
        '0d00.0000.0000.0000',
        '0e00.0000.0000.0000',
        '0f00.0000.0000.0000',
        '1000.0000.0000.0000',
        '1600.0000.0000.0000',
        '1700.0000.0000.0000',
        '1800.0000.0000.0000',
        '1900.0000.0000.0000',
        '1a00.0000.0000.0000',
        '2000.0000.0000.0000',
        '2100.0000.0000.0000',
        '2200.0000.0000.0000',
        '2300.0000.0000.0000',
        '2400.0000.0000.0000',
        '2a00.0000.0000.0000',
        '2b00.0000.0000.0000',
        '2c00.0000.0000.0000',
        '2d00.0000.0000.0000',
        '2e00.0000.0000.0000'
        # '0066.0066.0066.0066'
    ],

# # 49 nodes 2 borders
#  "initial_network": [
#         '0001.0001.0001.0001',
#         '0200.0000.0000.0000',
#         '0300.0000.0000.0000',
#         '0400.0000.0000.0000',
#         '0500.0000.0000.0000',
#         '0600.0000.0000.0000',
#         '0700.0000.0000.0000',
#         '0800.0000.0000.0000',
#         '0c00.0000.0000.0000',
#         '0d00.0000.0000.0000',
#         '0e00.0000.0000.0000',
#         '0f00.0000.0000.0000',
#         '1000.0000.0000.0000',
#         '1100.0000.0000.0000',
#         '1200.0000.0000.0000',
#         '1600.0000.0000.0000',
#         '1700.0000.0000.0000',
#         '1800.0000.0000.0000',
#         '1900.0000.0000.0000',
#         '1a00.0000.0000.0000',
#         '1b00.0000.0000.0000',
#         '1c00.0000.0000.0000',
#         '2000.0000.0000.0000',
#         '2100.0000.0000.0000',
#         '2200.0000.0000.0000',
#         '2300.0000.0000.0000',
#         '2400.0000.0000.0000',
#         '2500.0000.0000.0000',
#         '2600.0000.0000.0000',
#         '2a00.0000.0000.0000',
#         '2b00.0000.0000.0000',
#         '2c00.0000.0000.0000',
#         '2d00.0000.0000.0000',
#         '2e00.0000.0000.0000',
#         '2f00.0000.0000.0000',
#         '3000.0000.0000.0000',
#         '3400.0000.0000.0000',
#         '3500.0000.0000.0000',
#         '3600.0000.0000.0000',
#         '3700.0000.0000.0000',
#         '3800.0000.0000.0000',
#         '3900.0000.0000.0000',
#         '3a00.0000.0000.0000',
#         '3e00.0000.0000.0000',
#         '3f00.0000.0000.0000',
#         '4000.0000.0000.0000',
#         '4100.0000.0000.0000',
#         '4200.0000.0000.0000',
#         '4300.0000.0000.0000',
#         '4400.0000.0000.0000'
#         # '0066.0066.0066.0066'
#     ],

# # 101 nodes 2 borders
# "initial_network": [
#         '0001.0001.0001.0001',
#         '0200.0000.0000.0000',
#         '0300.0000.0000.0000',
#         '0400.0000.0000.0000',
#         '0500.0000.0000.0000',
#         '0600.0000.0000.0000',
#         '0700.0000.0000.0000',
#         '0800.0000.0000.0000',
#         '0900.0000.0000.0000',
#         '0a00.0000.0000.0000',
#         '0b00.0000.0000.0000',
#         '0c00.0000.0000.0000',
#         '0d00.0000.0000.0000',
#         '0e00.0000.0000.0000',
#         '0f00.0000.0000.0000',
#         '1000.0000.0000.0000',
#         '1100.0000.0000.0000',
#         '1200.0000.0000.0000',
#         '1300.0000.0000.0000',
#         '1400.0000.0000.0000',
#         '1500.0000.0000.0000',
#         '1600.0000.0000.0000',
#         '1700.0000.0000.0000',
#         '1800.0000.0000.0000',
#         '1900.0000.0000.0000',
#         '1a00.0000.0000.0000',
#         '1b00.0000.0000.0000',
#         '1c00.0000.0000.0000',
#         '1d00.0000.0000.0000',
#         '1e00.0000.0000.0000',
#         '1f00.0000.0000.0000',
#         '2000.0000.0000.0000',
#         '2100.0000.0000.0000',
#         '2200.0000.0000.0000',
#         '2300.0000.0000.0000',
#         '2400.0000.0000.0000',
#         '2500.0000.0000.0000',
#         '2600.0000.0000.0000',
#         '2700.0000.0000.0000',
#         '2800.0000.0000.0000',
#         '2900.0000.0000.0000',
#         '2a00.0000.0000.0000',
#         '2b00.0000.0000.0000',
#         '2c00.0000.0000.0000',
#         '2d00.0000.0000.0000',
#         '2e00.0000.0000.0000',
#         '2f00.0000.0000.0000',
#         '3000.0000.0000.0000',
#         '3100.0000.0000.0000',
#         '3200.0000.0000.0000',
#         '3300.0000.0000.0000',
#         '3400.0000.0000.0000',
#         '3500.0000.0000.0000',
#         '3600.0000.0000.0000',
#         '3700.0000.0000.0000',
#         '3800.0000.0000.0000',
#         '3900.0000.0000.0000',
#         '3a00.0000.0000.0000',
#         '3b00.0000.0000.0000',
#         '3c00.0000.0000.0000',
#         '3d00.0000.0000.0000',
#         '3e00.0000.0000.0000',
#         '3f00.0000.0000.0000',
#         '4000.0000.0000.0000',
#         '4100.0000.0000.0000',
#         '4200.0000.0000.0000',
#         '4300.0000.0000.0000',
#         '4400.0000.0000.0000',
#         '4500.0000.0000.0000',
#         '4600.0000.0000.0000',
#         '4700.0000.0000.0000',
#         '4800.0000.0000.0000',
#         '4900.0000.0000.0000',
#         '4a00.0000.0000.0000',
#         '4b00.0000.0000.0000',
#         '4c00.0000.0000.0000',
#         '4d00.0000.0000.0000',
#         '4e00.0000.0000.0000',
#         '4f00.0000.0000.0000',
#         '5000.0000.0000.0000',
#         '5100.0000.0000.0000',
#         '5200.0000.0000.0000',
#         '5300.0000.0000.0000',
#         '5400.0000.0000.0000',
#         '5500.0000.0000.0000',
#         '5600.0000.0000.0000',
#         '5700.0000.0000.0000',
#         '5800.0000.0000.0000',
#         '5900.0000.0000.0000',
#         '5a00.0000.0000.0000',
#         '5b00.0000.0000.0000',
#         '5c00.0000.0000.0000',
#         '5d00.0000.0000.0000',
#         '5e00.0000.0000.0000',
#         '5f00.0000.0000.0000',
#         '6000.0000.0000.0000',
#         '6100.0000.0000.0000',
#         '6200.0000.0000.0000',
#         '6300.0000.0000.0000',
#         '6400.0000.0000.0000',
#         '6500.0000.0000.0000'
#         # '0066.0066.0066.0066'
#     ],

    "border_router": [
        ('0001.0001.0001.0001', "fd00::201:1:1:1")
        # ('0066.0066.0066.0066', "fd01::266:66:66:66")
    ]
}
