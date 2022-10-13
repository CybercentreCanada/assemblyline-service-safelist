import csv
import os
import tempfile
import time
import zipfile
import requests

from assemblyline.common.digests import get_sha256_for_file
from assemblyline.common.isotime import iso_to_epoch
from assemblyline.odm.models.service import Service, UpdateSource
from assemblyline_client import get_client, Client
from assemblyline_v4_service.updater.updater import ServiceUpdater, temporary_api_key
from assemblyline_v4_service.updater.helper import SkipSource, BLOCK_SIZE, add_cacert

import pycdlib

UI_SERVER = os.getenv('UI_SERVER', 'https://nginx')
UPDATE_DIR = os.path.join(tempfile.gettempdir(), 'safelist_updates')
HASH_LEN = 1000


def url_download(source, target_path, logger, previous_update=None):
    uri = source['uri']
    username = source.get('username', None)
    password = source.get('password', None)
    ca_cert = source.get('ca_cert', None)
    ignore_ssl_errors = source.get('ssl_ignore_errors', False)
    auth = (username, password) if username and password else None

    proxy = source.get('proxy', None)
    headers = source.get('headers', None)

    logger.info(f"This source is configured to {'ignore SSL errors' if ignore_ssl_errors else 'verify SSL'}.")
    if ca_cert:
        logger.info("A CA certificate has been provided with this source.")
        add_cacert(ca_cert)

    # Create a requests session
    session = requests.Session()
    session.verify = not ignore_ssl_errors

    # Let https requests go through proxy
    if proxy:
        os.environ['https_proxy'] = proxy

    try:
        if isinstance(previous_update, str):
            previous_update = iso_to_epoch(previous_update)

        # Check the response header for the last modified date
        response = session.head(uri, auth=auth, headers=headers)
        last_modified = response.headers.get('Last-Modified', None)
        if last_modified:
            # Convert the last modified time to epoch
            last_modified = time.mktime(time.strptime(last_modified, "%a, %d %b %Y %H:%M:%S %Z"))

            # Compare the last modified time with the last updated time
            if previous_update and last_modified <= previous_update:
                # File has not been modified since last update, do nothing
                logger.info("The file has not been modified since last run, skipping...")
                return False

        if previous_update:
            previous_update = time.strftime("%a, %d %b %Y %H:%M:%S %Z", time.gmtime(previous_update))
            if headers:
                headers['If-Modified-Since'] = previous_update
            else:
                headers = {'If-Modified-Since': previous_update}

        logger.info(f"Downloading file from: {source['uri']}")
        with session.get(uri, auth=auth, headers=headers, stream=True) as response:
            # Check the response code
            if response.status_code == requests.codes['not_modified']:
                # File has not been modified since last update, do nothing
                logger.info("The file has not been modified since last run, skipping...")
                raise SkipSource
            elif response.ok:
                with open(target_path, 'wb') as f:
                    for content in response.iter_content(BLOCK_SIZE):
                        f.write(content)

                # Clear proxy setting
                if proxy:
                    del os.environ['https_proxy']

                # Return file_path
                return True
    except requests.Timeout:
        pass
    except Exception as e:
        # Catch all other types of exceptions such as ConnectionError, ProxyError, etc.
        logger.warning(str(e))
        return False
    finally:
        # Close the requests session
        session.close()


def download_extract_zip(logger, source, target_path, extracted_path, UPDATE_DIR, previous_update):
    if url_download(source, target_path, logger, previous_update=previous_update):
        logger.info(f"Unzipping downloaded file {target_path}... into {extracted_path}")

        with zipfile.ZipFile(target_path) as z:
            z.extract(source['pattern'], UPDATE_DIR)
        os.unlink(target_path)

        os.rename(os.path.join(UPDATE_DIR, source['pattern']), extracted_path)
        logger.info(f"Unzip finished, created file {extracted_path}")


def download_extract_iso(logger, source, target_path, extracted_path, UPDATE_DIR, previous_update):
    # NSRL ISO only!
    if url_download(source, target_path, logger, previous_update=previous_update):
        zip_file = f"{target_path}.zip"

        iso = pycdlib.PyCdlib()
        iso.open(target_path)

        logger.info("Extracting NSRLFILE.ZIP form ISO...")
        with open(zip_file, "wb") as zip_fh:
            iso.get_file_from_iso_fp(zip_fh, iso_path='/NSRLFILE.ZIP;1')
        iso.close()
        os.unlink(target_path)

        logger.info(f"Unzipping {zip_file} ...")
        with zipfile.ZipFile(zip_file) as z:
            z.extract(source['pattern'], UPDATE_DIR)
        os.unlink(zip_file)

        os.rename(os.path.join(UPDATE_DIR, source['pattern']), extracted_path)
        logger.info(f"Unzip finished, created file {extracted_path}")


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

    def do_source_update(self, service: Service) -> None:
        self.log.info(f"Connecting to Assemblyline API: {UI_SERVER}...")
        run_time = time.time()
        username = self.ensure_service_account()
        with temporary_api_key(self.datastore, username) as api_key:
            client = get_client(UI_SERVER, apikey=(username, api_key), verify=False)
            old_update_time = self.get_source_update_time()

            self.log.info("Connected!")

            # Parse updater configuration
            previous_hashes: dict[str, str] = self.get_source_extra()
            sources: dict[str, UpdateSource] = {_s['name']: _s for _s in service.update_config.sources}
            files_sha256: dict[str, str] = {}

            # Go through each source and download file
            for source_name, source_obj in sources.items():
                source = source_obj.as_primitives()
                uri: str = source['uri']
                self.log.info(f"Processing source: {source['name'].upper()}")
                download_name = os.path.basename(uri)
                target_path = os.path.join(tempfile.mkdtemp(), download_name)
                extracted_path = os.path.join(UPDATE_DIR, source['name'])

                try:
                    if download_name.endswith(".zip"):
                        download_extract_zip(self.log, source, target_path,
                                             extracted_path, UPDATE_DIR, previous_update=old_update_time)
                    elif download_name.endswith(".iso"):
                        download_extract_iso(self.log, source, target_path,
                                             extracted_path, UPDATE_DIR, previous_update=old_update_time)
                    else:
                        url_download(source, extracted_path, self.log, previous_update=old_update_time)

                    if os.path.exists(extracted_path) and os.path.isfile(extracted_path):
                        previous_hashes[source_name] = {extracted_path: get_sha256_for_file(extracted_path)}
                        self.import_update(extracted_path, client, source_name)

                except SkipSource:
                    if source_name in previous_hashes:
                        files_sha256[source_name] = previous_hashes[source_name]
                    continue

        self.set_source_update_time(run_time)
        self.set_source_extra(files_sha256)
        self.set_active_config_hash(self.config_hash(service))
        self.local_update_flag.set()


if __name__ == '__main__':
    with SafelistUpdateServer(default_pattern="*.txt") as server:
        server.serve_forever()
