import aiocoap.resource as resource
import aiocoap
import logging
import threading

from base_station.revoke_process import RevokeProcess
from base_station.helper.mac_conversion import MAC_byte_to_string
from config import CONFIG

logger = logging.getLogger(name='base_station.post_handler')


class AkesRevokeResource(resource.Resource):
    """Example resource which supports the GET and PUT methods. It sends large
    responses, which trigger blockwise transfer."""

    def __init__(self):
        super().__init__()

    async def render_post(self, request):
        start = 0
        end = CONFIG["ll_address_size"]
        border_router = request.payload[start:end]

        start = end
        end += 1
        number_of_replies = int.from_bytes(request.payload[start:end], byteorder='big')

        start = end
        end += 1
        number_of_neighbors = int.from_bytes(request.payload[start: end], byteorder='big')

        replies = []
        for i in range(number_of_replies):
            start = end
            end += CONFIG["ll_address_size"]
            replies.append(request.payload[start:end])

        neighbors = []
        for i in range(number_of_neighbors):
            start = end
            end += CONFIG["ll_address_size"]
            neighbors.append(request.payload[start:end])
        logger.debug("last start and end: {} and {}".format(start, end))
        logger.debug("Border Router: " + MAC_byte_to_string(border_router))
        logger.debug("Number of replies: " + repr(number_of_replies))
        for e in replies:
            logger.debug(MAC_byte_to_string(e))
        logger.debug("Number of neighbors: " + repr(number_of_neighbors))
        for e in neighbors:
            logger.debug(MAC_byte_to_string(e))

        t = threading.Thread(
            target=RevokeProcess().process_update,
            args=(border_router, replies, neighbors),
            daemon=True,
            name="Name")
        t.start()
        return aiocoap.Message(payload=b'OK', code=aiocoap.CREATED)
