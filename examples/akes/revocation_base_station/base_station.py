import logging
import signal
from asyncio import sleep
import threading
import asyncio

from config import CONFIG
from base_station.logging import setup_logging
from base_station.coap_server import CoAPServer
from base_station.revoke_process import RevokeProcess

logger = logging.getLogger(name='base_station')


class BaseStation:

    def __init__(self):
        setup_logging()
        self.revocation_process = RevokeProcess()
        self.aio_loop = asyncio.new_event_loop()
        self._start_server()
        signal.signal(signal.SIGINT, self._stop_server)
        signal.signal(signal.SIGTERM, self._stop_server)

    async def run(self):
        if not CONFIG['on_mote']:

            await self._run_in_simulation()

            # client = await Context.create_client_context()
            #
            # payload = build_payload(
            #     control_byte_default,
            #     MAC_string_to_byte('0200.0000.0000.0000'),
            #     [MAC_string_to_byte('0001.0001.0001.0001')]
            # )
            #
            # request = Message(code=POST, payload=payload)
            # request.opt.uri_host = CONFIG['host']
            # request.opt.uri_path = tuple(filter(None, CONFIG['path'].split('/')))
            #
            # try:
            #     response = await client.request(request).response
            # except Exception as e:
            #     print('Failed to fetch resource:')
            #     print(e)
            # else:
            #     print('Result: %s\n%r' % (response.code, response.payload))
            #
            # payload = build_payload(
            #     control_byte_default,
            #     MAC_string_to_byte('0200.0000.0000.0000'),
            #     [MAC_string_to_byte('0300.0000.0000.0000'), MAC_string_to_byte('0400.0000.0000.0000')]
            # )
            #
            # request = Message(code=POST, payload=payload)
            # request.opt.uri_host = CONFIG['host']
            # request.opt.uri_path = tuple(filter(None, CONFIG['path'].split('/')))
            #
            # try:
            #     response = await client.request(request).response
            # except Exception as e:
            #     print('Failed to fetch resource:')
            #     print(e)
            # else:
            #     print('Result: %s\n%r' % (response.code, response.payload))

    async def _run_in_simulation(self):
        while True:
            if self.revocation_process.in_progress():
                sleep(1)
                continue

            print("Please select a node from the network you would wish to remove:\n")

            print(self.revocation_process.print_revokeable_nodes())

            selection = input("Remove node number: ")

            print("Going to remove node number {}".format(selection))

            # TODO implement auto process with RevokeProcess

            with self.revocation_process:
                await self.revocation_process.start_revocation_of_id(selection)

    def _start_server(self):
        t = threading.Thread(target=CoAPServer().run, args=(self.aio_loop,), daemon=False, name="CoAP Server")
        t.start()

    def _stop_server(self, *args, **kwargs):
        print("Shutting down. Please wait...")
        self.aio_loop.stop()


if __name__ == '__main__':
    asyncio.get_event_loop().run_until_complete(BaseStation().run())
