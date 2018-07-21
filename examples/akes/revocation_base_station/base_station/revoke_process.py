import logging
from asyncio import sleep
from threading import RLock, current_thread
import asyncio
from aiocoap import *
from tqdm import tqdm

from base_station.node_store import NodeStore
from config import CONFIG
from base_station.helper.mac_conversion import MAC_byte_to_string, MAC_bytearray_to_stringarray

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
            self._progress = None

        def in_progress(self):
            return self._in_progress

        def print_revokeable_nodes(self):
            return str(self.nodes)

        async def start_revocation_of_id(self, selection):
            with self._lock, self.nodes:
                self._in_progress = True
                self._revocation_id = selection
                self._progress = tqdm(total=self.nodes.network_size() - 1, ascii=True, unit="nodes", )
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

            self._update_progress(len(replies))

            await self._check_for_termination()

        def _build_payload(self, control_byte, revoke_node, dst_node_addrs=None):
            payload = b''
            payload += control_byte
            payload += revoke_node
            if dst_node_addrs:
                payload += bytes([len(dst_node_addrs)])
                for addr in dst_node_addrs:
                    payload += addr
            return payload

        async def _send_message(self, border_router_ip, control_byte, destinations=None, revoke_node=None):
            client = await Context.create_client_context()
            if not revoke_node:
                revoke_node = self.nodes.get_node_with_id(self._revocation_id)
            logger.debug(destinations)
            logger.debug("Sending revocation message over {} to {}".format(border_router_ip, ", ".join(
                MAC_bytearray_to_stringarray(destinations))))
            payload = self._build_payload(
                control_byte,
                revoke_node,
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

        async def _check_for_termination(self):
            if self._pending or self._queue:
                return

            logger.info("Terminate revoke process")
            revoked_node = self.nodes.get_node_with_id(self._revocation_id)
            self.nodes.remove_node_id(self._revocation_id)

            for router_mac, router_ip in self.nodes.iter_border_router():
                await self._send_message(router_ip, self._control_byte_terminate, revoke_node=revoked_node)

            self._revocation_id = None
            self._pending = []
            self._queue = []
            self._revoked = []
            self._progress.close()
            self._progress = None
            self._in_progress = False


        def _update_progress(self, delta):
            self._progress.update(delta)

        async def _process_queue(self):

            message_groups = {}
            for router, node in self._queue:
                if list(filter(lambda t: t[1] == node, self._pending)):
                    continue
                try:
                    message_groups[router].append(node)
                except KeyError:
                    message_groups[router] = [node]

                self._pending.append((router, node))
                self._queue.remove((router, node))

            for router in message_groups:
                await self._send_message(self.nodes.get_router_ip(router),
                                         self._control_byte_default,
                                         message_groups[router]
                                         )

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