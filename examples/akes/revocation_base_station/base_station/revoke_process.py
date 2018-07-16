import logging
from threading import RLock, current_thread

logger = logging.getLogger(name='base_station.revoke_process')


class RevokeProcess:

    def __init__(self):
        self._lock = RLock()
        self._in_progress = False

    def in_progress(self):
        return self._in_progress

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
