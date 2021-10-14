
from assemblyline.common.isotime import now, epoch_to_iso
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Heuristic, Result, ResultSection


class Safelist(ServiceBase):
    def __init__(self, config=None):
        super(Safelist, self).__init__(config)
        self.api_interface = None
        # Default cache timeout invalidates the cache every 30 minutes
        self.timeout = 1800

    def start(self):
        # Initialize session
        self.api_interface = self.get_api_interface()
        self.timeout = self.config.get('cache_timeout_seconds', self.timeout)

    def get_tool_version(self):
        epoch = now()
        return epoch_to_iso(epoch - (epoch % self.timeout))

    # Utilizes the Safelist API, doesn't need to download files from updater
    def _download_rules(self):
        pass

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
            data = self.api_interface.lookup_safelist(qhash)
            if data and data['enabled'] and data['type'] == "file":
                # Create a section per source
                for source in data['sources']:
                    if source['type'] == 'user':
                        msg = f"User {source['name']} deemed this file as safe for the following reason(s):"
                        heur_id = 2
                    else:
                        msg = f"External safelist source {source['name']} deems this file as safe " \
                            "for the following reason(s):"
                        heur_id = 1

                    result.add_section(
                        ResultSection(
                            msg, heuristic=Heuristic(heur_id, signature=f"SAFELIST_{qhash}"),
                            body="\n".join(source['reason'])))

                # Stop processing, the file is safe
                request.drop()

        request.result = result
