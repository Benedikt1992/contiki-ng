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
        # TODO prepare payload
        t = threading.Thread(target=RevokeProcess().process_update, args=(5,), daemon=True, name="Name")
        t.start()
        return aiocoap.Message(payload=b'OK', code=aiocoap.CREATED)
