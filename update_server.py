import csv
import os
import pycdlib
import requests
import subprocess
import tempfile
import time

from assemblyline.common.digests import get_sha256_for_file
from assemblyline.odm.models.service import Service, UpdateSource
from assemblyline_client import get_client, Client
from assemblyline_v4_service.updater.updater import ServiceUpdater, temporary_api_key
from assemblyline_v4_service.updater.helper import add_cacert, BLOCK_SIZE, SkipSource, urlparse


UI_SERVER = os.getenv('UI_SERVER', 'https://nginx')
UI_SERVER_CA = os.environ.get('AL_ROOT_CA', '/etc/assemblyline/ssl/al_root-ca.crt')
HASH_LEN = 1000


def url_download(source, previous_update=None, logger=None, output_dir=None):
    """

    :param source:
    :param previous_update:
    :return:
    """
    name = source['name']
    uri = source['uri']
    pattern = source.get('pattern', None)
    username = source.get('username', None)
    password = source.get('password', None)
    ca_cert = source.get('ca_cert', None)
    ignore_ssl_errors = source.get('ssl_ignore_errors', False)
    auth = (username, password) if username and password else None

    proxy = source.get('proxy', None)
    headers_list = source.get('headers', [])
    headers = {}
    [headers.update({header['name']: header['value']}) for header in headers_list]

    logger.info(f"{name} source is configured to {'ignore SSL errors' if ignore_ssl_errors else 'verify SSL'}.")
    if ca_cert:
        logger.info("A CA certificate has been provided with this source.")
        add_cacert(ca_cert)

    # Create a requests session
    session = requests.Session()
    session.verify = not ignore_ssl_errors

    # Let https requests go through proxy
    proxies = {'http': proxy, 'https': proxy} if proxy else None

    try:
        response = None
        with tempfile.NamedTemporaryFile('w') as private_key_file:
            if source.get('private_key'):
                logger.info('A private key has been provided with this source')
                private_key_file.write(source['private_key'])
                private_key_file.seek(0)
                session.cert = private_key_file.name

            # Check the response header for the last modified date
            response = session.head(uri, auth=auth, headers=headers, proxies=proxies)
            last_modified = response.headers.get('Last-Modified', None)
            if last_modified:
                # Convert the last modified time to epoch
                last_modified = time.mktime(time.strptime(last_modified, "%a, %d %b %Y %H:%M:%S %Z"))

                # Compare the last modified time with the last updated time
                if previous_update and last_modified <= previous_update:
                    # File has not been modified since last update, do nothing
                    raise SkipSource()

            if previous_update:
                previous_update = time.strftime("%a, %d %b %Y %H:%M:%S %Z", time.gmtime(previous_update))
                if headers:
                    headers['If-Modified-Since'] = previous_update
                else:
                    headers = {'If-Modified-Since': previous_update}

            response = session.get(uri, auth=auth, headers=headers, proxies=proxies, stream=True)

        # Check the response code
        if response.status_code == requests.codes['not_modified']:
            # File has not been modified since last update, do nothing
            raise SkipSource()
        elif response.ok:
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)

            file_name = os.path.basename(urlparse(uri).path)
            file_path = os.path.join(output_dir, file_name)
            with open(file_path, 'wb') as f:
                for content in response.iter_content(BLOCK_SIZE):
                    f.write(content)

            return file_path
        else:
            logger.warning(f"Download not successful: {response.content}")
            return None

    except SkipSource:
        # Raise to calling function for handling
        raise
    except Exception as e:
        # Catch all other types of exceptions such as ConnectionError, ProxyError, etc.
        logger.warning(str(e))
        return False
    finally:
        # Close the requests session
        session.close()


def extract_safelist(file, pattern, logger):
    logger.info(f'Extracting safelist file from {file}')
    dir = os.path.dirname(file)
    try:
        # Check if we're dealing with an NSRL ISO
        iso = pycdlib.PyCdlib()
        iso.open(file)
        iso.get_entry('/NSRLFILE.ZIP;1')
        del iso
        logger.info(f'{file} is an NSRL ISO. Extracting embedded "NSRLFile.txt.zip"..')

        # If we are, then we need to extract the embedded file as assign that as the 'true' file to be extracted
        zip_file = os.path.join(dir, 'NSRLFile.txt.zip')
        subprocess.run(['7z', 'x', '-y', file, f'-o{dir}', 'NSRLFile.txt.zip'], capture_output=True)
        os.unlink(file)
        file = zip_file

    except pycdlib.pycdlibexception.PyCdlibInvalidInput:
        # ISO, but not an NSRL ISO
        pass

    except pycdlib.pycdlibexception.PyCdlibInvalidISO:
        # Not an ISO, treat as normal ZIP (or something that 7z can handle)
        pass

    logger.info(f"Extracting {pattern} from {file}..")
    safelist_file = os.path.join(dir, pattern)
    subprocess.run(['7z', 'x', '-y', file, f'-o{dir}', pattern], capture_output=True)
    logger.info(f'Extraction complete: {safelist_file}')
    os.unlink(file)

    return safelist_file


class SafelistUpdateServer(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def import_update(self, file_path, client: Client, source_name: str, default_classification=None):
        success = 0
        with open(file_path) as fh:
            reader = csv.reader(fh, delimiter=',', quotechar='"')
            hash_list = []

            def add_hash_set() -> int:
                try:
                    resp = client._connection.put("api/v4/safelist/add_update_many/", json=hash_list)
                    return resp['success']
                except Exception as e:
                    self.log.error(f"Failed to insert hash into safelist: {str(e)}")
                return 0

            for line in reader:
                sha1, md5, _, filename, size = line[:5]
                if sha1 == "SHA-1":
                    continue

                data = {
                    "file": {"name": [filename], "size": size},
                    "hashes": {"md5": md5.lower(), "sha1": sha1.lower()},
                    "sources": [
                        {"name": source_name,
                            'type': 'external',
                            "reason": [f"Exist in source as {filename}"]}
                    ],
                    'type': "file"
                }
                hash_list.append(data)

                if len(hash_list) % HASH_LEN == 0:
                    # Add 1000 item batch, record success, then start anew
                    success += add_hash_set()
                    hash_list = []

            # Add any remaining items to safelist (if any)
            success += add_hash_set()

        os.unlink(file_path)
        self.log.info(f"Import finished. {success} hashes have been processed.")

    def do_local_update(self) -> None:
        pass

    def do_source_update(self, service: Service, specific_sources: list[str] = []) -> None:
        self.log.info(f"Connecting to Assemblyline API: {UI_SERVER}...")
        run_time = time.time()
        username = self.ensure_service_account()
        with temporary_api_key(self.datastore, username) as api_key:
            verify = None if not os.path.exists(UI_SERVER_CA) else UI_SERVER_CA
            client = get_client(UI_SERVER, apikey=(username, api_key), verify=verify)
            self.log.info("Connected!")

            # Parse updater configuration
            previous_hashes: dict[str, dict[str, str]] = self.get_source_extra()
            sources: dict[str, UpdateSource] = {_s['name']: _s for _s in service.update_config.sources}
            files_sha256: dict[str, dict[str, str]] = {}

            # Go through each source and download file
            for source_name, source_obj in sources.items():
                # Set current source for pushing state to UI
                self._current_source = source_name
                old_update_time = self.get_source_update_time()
                if specific_sources and source_name not in specific_sources:
                    # Parameter is used to determine if you want to update a specific source only
                    # Otherwise, assume we want to update all sources
                    continue

                self.push_status("UPDATING", "Starting..")
                source = source_obj.as_primitives()
                uri: str = source['uri']
                self.log.info(f"Processing source: {source['name'].upper()}")
                download_name = os.path.basename(uri)
                orig_source_pattern = source['pattern']
                source['pattern'] = f'.*{download_name}'

                with tempfile.TemporaryDirectory() as update_dir:
                    try:
                        self.push_status("UPDATING", "Pulling..")
                        # Pull sources from external locations (method depends on the URL)
                        file = url_download(source=source, previous_update=old_update_time, logger=self.log,
                                            output_dir=update_dir)

                        file = extract_safelist(file, orig_source_pattern, self.log)
                        # Add to collection of sources for caching purposes
                        self.log.info(f"Found new {self.updater_type} rule files to process for {source_name}!")
                        previous_hashes[source_name] = {file: get_sha256_for_file(file)}
                        # Import into Assemblyline
                        self.push_status("UPDATING", "Importing..")
                        self.import_update(file, client, source_name)
                        self.push_status("DONE", "Signature(s) Imported.")

                    except SkipSource:
                        # This source hasn't changed, no need to re-import into Assemblyline
                        self.log.info(f'No new {self.updater_type} rule files to process for {source_name}')
                        if source_name in previous_hashes:
                            files_sha256[source_name] = previous_hashes[source_name]
                        self.push_status("DONE", "Skipped.")
                    except Exception as e:
                        self.push_status("ERROR", str(e))
                        continue

                    self.set_source_update_time(run_time)
                    self.set_source_extra(files_sha256)
        self.set_active_config_hash(self.config_hash(service))
        self.local_update_flag.set()


if __name__ == '__main__':
    with SafelistUpdateServer(default_pattern="*.txt") as server:
        server.serve_forever()
