
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
        # Invalidate cache every 30 minutes
        # TODO: We could create an API endpoint that would lookup when the last entry in the DB is instead.
        return epoch_to_iso(epoch - (epoch % 1800))

    def execute(self, request):
        result = Result()

        hashes = []
        if self.config.get('lookup_sha256', False):
            hashes.append(request.sha256)
        if self.config.get('lookup_sha1', False):
            hashes.append(request.sha1)
        if self.config.get('lookup_md5', False):
            hashes.append(request.md5)

        for qhash in hashes:
            resp = self.session.get(f"{self.service_api_host}/api/v1/safelist/{qhash}/")
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
