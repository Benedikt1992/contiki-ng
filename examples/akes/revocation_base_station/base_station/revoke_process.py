import logging
from asyncio import sleep
from threading import RLock, current_thread
import asyncio
from aiocoap import *

from base_station.node_store import NodeStore
from config import CONFIG

logger = logging.getLogger(name='base_station.revoke_process')


class RevokeProcess:

    class __RevokeProcess:

        _control_byte_default = b'\x00'
        _control_byte_terminate = b'\x02'

        def __init__(self):
            self._lock = RLock()
            self._in_progress = False
            self.nodes = NodeStore()

        def in_progress(self):
            return self._in_progress

        def print_revokeable_nodes(self):
            return str(self.nodes)

        async def start_revocation_of_id(self, selection):
            with self._lock, self.nodes:
                self._in_progress = True
                client = await Context.create_client_context()

                for border_router in self.nodes.iter_border_router():
                    payload = self._build_payload(
                        self._control_byte_default,
                        self.nodes.get_node_with_id(selection),
                        [border_router]
                    )
                    request = Message(code=POST, payload=payload)
                    request.opt.uri_host = CONFIG['host']
                    request.opt.uri_path = tuple(filter(None, CONFIG['path'].split('/')))
                    try:
                        response = await client.request(request).response
                    except Exception as e:
                        print('Failed to fetch resource:')
                        print(e)
                    else:
                        print('Result: %s\n%r' % (response.code, response.payload))

        def process_update(self, *args, **kwargs):
            with self._lock:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(self._process_update(*args, **kwargs))
                loop.close()

        async  def _process_update(self, *args, **kwargs):
            # TODO process...
            client = await Context.create_client_context()
            print(args[0])

        def _build_payload(self, control_byte, revoke_node, dst_node_addrs):
            payload = b''
            payload += control_byte
            payload += revoke_node
            payload += bytes([len(dst_node_addrs)])
            for addr in dst_node_addrs:
                payload += addr
            return payload

        def __enter__(self):
            self._lock.acquire()

        def __exit__(self, exc_type, exc_val, exc_tb):
            self._lock.release()
            if exc_type or exc_val or exc_tb:
                logger.exception("Thread '{}' got an exception within a with \
                                   statement. Type: {}; Value: {}; Traceback:"
                                 .format(current_thread(),
                                         exc_type,
                                         exc_val))

    __instance = None

    def __new__(cls):
        """Create a singleton instance of the object."""
        if cls.__instance is None:
            cls.__instance = RevokeProcess.__RevokeProcess()
        return cls.__instance

    def __getattr__(self, name):
        return getattr(self.__instance, name)

    def __setattr__(self, name, value):
        return setattr(self.__instance, name, value)