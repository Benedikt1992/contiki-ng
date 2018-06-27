# Revocation Base Station

TODO

## Requirements
The Base Station uses Python 3.x (tested with 3.5). You can install it from https://www.python.org/downloads/ 

To install all requirements run `pip install --trusted-host pypi.python.org -r requirements.txt`

## How to use

TODO

## Configuration

The behaviour of the Base Station is configurable in some cases. This section explains the use of the different key in the file `config.py`

 - `on_mote`  
 `True` means interact with physical devices. `False` means interact with cooja demo.
 - `cooja_malicious_node_id`  
 If `on_mote` is `False` this value gives the id of the cooja node that sould be revoked from the network as number.
 