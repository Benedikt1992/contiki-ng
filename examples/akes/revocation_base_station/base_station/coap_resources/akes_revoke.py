import aiocoap.resource as resource
import aiocoap
import logging

logger = logging.getLogger(name='base_station.post_handler')


class AkesRevokeResource(resource.Resource):
    """Example resource which supports the GET and PUT methods. It sends large
    responses, which trigger blockwise transfer."""

    def __init__(self):
        super().__init__()

    async def render_post(self, request):
        print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        return aiocoap.Message(payload=b'OK', code=aiocoap.CREATED)
