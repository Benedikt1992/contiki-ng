import aiocoap.resource as resource
import aiocoap
import logging
import threading

from base_station.revoke_process import RevokeProcess

logger = logging.getLogger(name='base_station.post_handler')


class AkesRevokeResource(resource.Resource):
    """Example resource which supports the GET and PUT methods. It sends large
    responses, which trigger blockwise transfer."""

    def __init__(self):
        super().__init__()

    async def render_post(self, request):
        print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        print(request.remote.hostinfo)
        print(repr(request.payload))
        border_router = request.payload[0:8]
        number_of_replies = request.payload[8:8+1]
        replies = []
        for i in range(number_of_replies):
            start = (8+1)+i*8
            end = (8+1)+(i+1)*8
            replies.append(request.payload[start:end])
        

        # TODO prepare payload
        t = threading.Thread(target=RevokeProcess().process_update, args=(5,), daemon=True, name="Name")
        t.start()
        return aiocoap.Message(payload=b'OK', code=aiocoap.CREATED)
