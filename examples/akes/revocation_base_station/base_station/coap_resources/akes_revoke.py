from coapthon.resources.resource import Resource
import coapthon.defines as defines
import logging

logger = logging.getLogger(name='base_station.post_handler')
class AkesRevokeResource(Resource):
    def __init__(self, name="AKES Revoke", coap_server=None):
        super(AkesRevokeResource, self).__init__(name, coap_server, visible=True,
                                            observable=True, allow_children=True)
        self.payload = "AKES Revoke"

    def render_POST_advanced(self, request, response):
        self.payload = request.payload
        from coapthon.messages.response import Response
        assert (isinstance(response, Response))
        response.payload = "OK"
        response.code = defines.Codes.CREATED.number
        logger.debug("render_POST_advanced")
        print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        return self, response

    def render_POST(self, request):
        print("-------------------------------------------------------------")
        return self
