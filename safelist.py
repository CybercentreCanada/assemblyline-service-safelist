
import os

import requests

from assemblyline.common.isotime import now, epoch_to_iso
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Heuristic, Result, ResultSection


class Safelist(ServiceBase):
    def __init__(self, config=None):
        super(Safelist, self).__init__(config)
        self.session = None
        self.service_api_host = None

    def start(self):
        # Initialize session
        self.service_api_host = os.environ.get("SERVICE_API_HOST", "http://localhost:5003")
        self.session = requests.Session()
        self.session.headers.update(dict(
            X_APIKEY=os.environ.get("SERVICE_API_AUTH_KEY", "ThisIsARandomAuthKey...ChangeMe!"),
            container_id=os.environ.get('HOSTNAME', 'dev-service'),
            service_name=self.service_attributes.name,
            service_version=self.service_attributes.version
        ))

    def get_tool_version(self):
        epoch = now()
        return epoch_to_iso(epoch - (epoch % 1800))

    def execute(self, request):
        result = Result()
        file_hash = request.sha256
        resp = self.session.get(f"{self.service_api_host}/api/v1/safelist/{file_hash}/")
        if resp.ok:
            data = resp.json()['api_response']
            # Create a section per source
            for source in data['sources']:
                if source['type'] == 'user':
                    msg = f"User {source['name']} deemed this file as safe for the following reason(s):"
                else:
                    msg = f"External safelist source {source['name']} deems this file as safe " \
                        "for the following reason(s):"

                result.add_section(ResultSection(msg, heuristic=Heuristic(1), body="\n".join(source['reason'])))

            # Stop processing, the file is safe
            request.drop()

        request.result = result
