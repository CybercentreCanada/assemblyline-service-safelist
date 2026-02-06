
import hashlib
from assemblyline.common import forge
from assemblyline.common.isotime import epoch_to_iso, now
from assemblyline_v4_service.common.base import ServiceBase, SERVICE_READY_PATH 
from assemblyline_v4_service.common.result import Heuristic, Result, ResultSection

classification = forge.get_classification()


class Safelist(ServiceBase):
    def __init__(self, config=None):
        super(Safelist, self).__init__(config)
        # Default cache timeout invalidates the cache every 30 minutes
        self.timeout = 1800

    def start(self):
        self.timeout = self.config.get('cache_timeout_seconds', self.timeout)

    def get_tool_version(self):
        epoch = now()
        return epoch_to_iso(epoch - (epoch % self.timeout))

    # Utilizes the Safelist API, doesn't need to download files from updater
    def _download_rules(self):
        with open(SERVICE_READY_PATH, 'w'):
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

        if request.file_type.startswith("uri/") and request.task.fileinfo.uri_info:
            for analytic_type in ['static', 'dynamic']:
                hashed_value = f"network.{analytic_type}.uri: {request.task.fileinfo.uri_info.uri}".encode('utf8')
                hashes.append(hashlib.sha256(hashed_value).hexdigest())

        for qhash in hashes:
            data = self.api_interface.lookup_safelist(qhash)
            if data and data['enabled']:
                # Check the type of hit we got
                is_file = False
                is_uri = False
                safe_type = "unknown"
                if data['type'] == "file":
                    is_file = True
                    safe_type = "file"
                if data['type'] == "tag" and data['tag']['type'] in ['network.static.uri', 'network.dynamic.uri']:
                    is_uri = True
                    safe_type = "URI"

                if is_file or is_uri:
                    # Create a section per source
                    for source in data['sources']:
                        if source['type'] == 'user':
                            msg = f"User {source['name']} deemed this {safe_type} as safe for the following reason(s):"
                            heur_id = 2
                        else:
                            msg = f"External safelist source {source['name']} deems this {safe_type} as safe " \
                                "for the following reason(s):"
                            heur_id = 1

                        result.add_section(
                            ResultSection(
                                msg, heuristic=Heuristic(heur_id, signature=f"SAFELIST_{qhash}"),
                                body="\n".join(source['reason']),
                                classification=data.get('classification', classification.UNRESTRICTED)))

                    # Stop processing, the file is safe
                    request.drop()

        request.result = result
