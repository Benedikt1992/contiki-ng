import logging
from asyncio import sleep
from threading import RLock, current_thread
import asyncio
from aiocoap import *

from base_station.node_store import NodeStore
from config import CONFIG
from base_station.helper.mac_conversion import MAC_byte_to_string

logger = logging.getLogger(name='base_station.revoke_process')


class RevokeProcess:

    class __RevokeProcess:

        _control_byte_default = b'\x00'
        _control_byte_terminate = b'\x02'

        def __init__(self):
            self._lock = RLock()
            self._in_progress = False
            self.nodes = NodeStore()
            self._revocation_id = None
            self._pending = []
            self._queue = []
            self._revoked = []

        def in_progress(self):
            return self._in_progress

        def print_revokeable_nodes(self):
            return str(self.nodes)

        async def start_revocation_of_id(self, selection):
            with self._lock, self.nodes:
                self._in_progress = True
                self._revocation_id = selection
                # TODO check if it is the only left border router
                # TODO only send to border routers that are not revoked if it is a border router
                for border_router_id, border_router_ip in self.nodes.iter_border_router():
                    self._pending.append((border_router_id, border_router_id))
                    await self._send_message(
                        border_router_ip,
                        self._control_byte_default,
                        [border_router_id]
                    )

        def process_update(self, *args):
            if not self.in_progress():
                logger.info("Update function called without pending revocation process.")
                return
            with self._lock:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(self._process_update(*args))
                loop.close()

        async def _process_update(self, border_router, replies, neighbors):
            for reply in replies:
                if not list(filter(lambda t: t == (border_router, reply), self._pending)):
                    raise AttributeError("Reply {} is not pending.".format(MAC_byte_to_string(reply)))

                self._revoked.append(reply)
                self._pending = list(filter(
                    lambda t: t != (border_router, reply),
                    self._pending
                ))
                self._queue = list(filter(
                    lambda t: t[1] != reply,
                    self._queue
                ))

            self._pending = list(filter(
                lambda t: t[0] != border_router,
                self._pending
            ))

            for neighbor in neighbors:
                if neighbor == self.nodes.get_node_with_id(self._revocation_id):
                    continue
                if not list(filter(lambda node_id: node_id == neighbor, self._revoked)):
                    self._queue.append((border_router, neighbor))

            await self._process_queue()

            self._update_progress()

            self._check_for_termination()

        def _build_payload(self, control_byte, revoke_node, dst_node_addrs):
            payload = b''
            payload += control_byte
            payload += revoke_node
            payload += bytes([len(dst_node_addrs)])
            for addr in dst_node_addrs:
                payload += addr
            return payload

        async def _send_message(self, border_router_ip, control_byte, destinations):
            client = await Context.create_client_context()
            payload = self._build_payload(
                control_byte,
                self.nodes.get_node_with_id(self._revocation_id),
                destinations
            )
            request = Message(code=POST, payload=payload)
            request.opt.uri_host = border_router_ip
            request.opt.uri_path = tuple(filter(None, CONFIG['path'].split('/')))
            #TODO give feedback about success
            try:
                response = await client.request(request).response
            except Exception as e:
                print('Failed to fetch resource:')
                print(e)
            else:
                print('Result: %s\n%r' % (response.code, response.payload))

        def _check_for_termination(self):
            if self._pending or self._queue:
                return

            logger.info("Terminate revoke process")
            # TODO
            '''
            Reset all fields
            remove node from NodeStore
            send termination to all border routers (that are left - maybe a border router got removed as well)
            '''

        def _update_progress(self):
            print("IN PROGESS. please wait...")
            # TODO

        async def _process_queue(self):
            for router, node in self._queue:
                if list(filter(lambda t: t[1] == node, self._pending)):
                    continue
                 #TODO group messages by router
                await self._send_message(self.nodes.get_router_ip(router),
                                         self._control_byte_default,
                                         [node]
                                         )
                self._pending.append((router, node))
                self._queue.remove((router, node))

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