import logging
from threading import RLock, current_thread

from config import CONFIG
from base_station.helper.mac_conversion import MAC_string_to_byte, MAC_byte_to_string

logger = logging.getLogger(name='base_station.node_store')


class NodeStore:

    def __init__(self):
        self._lock = RLock()
        self.network_nodes = []
        self.border_router = []
        self._load_initial_network()
        self._iter_index = 0

    def get_node_with_id(self, i):
        return self.network_nodes[int(i) - 1]

    def iter_border_router(self):
        return iter(self.border_router)

    def _load_initial_network(self):
        for mac in CONFIG["initial_network"]:
            self.network_nodes.append(MAC_string_to_byte(mac))

        for mac in CONFIG["border_router"]:
            self.border_router.append(MAC_string_to_byte(mac))

    def __str__(self):
        string = ""
        for node, i in zip(self.network_nodes, range(1, len(self.network_nodes) + 1)):
            string += "\t({}) {}\n".format(i, MAC_byte_to_string(node))
        return string

    def __iter__(self):
        self._iter_index = 0
        return self

    def __next__(self):
        if self._iter_index >= len(self.network_nodes):
            raise StopIteration
        self._iter_index += 1
        try:
            return self.network_nodes[self._iter_index - 1]
        except:
            raise IndexError

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
