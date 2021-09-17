import csv
import logging
import os
import shutil
import tempfile
import time
import zipfile
from zipfile import ZipFile

import certifi
import requests
from assemblyline.common import forge
from assemblyline.common import log as al_log
from assemblyline.common.isotime import epoch_to_iso, iso_to_epoch
from assemblyline.odm.models.service import Service, UpdateSource

import pycdlib
from assemblyline_client import get_client
from assemblyline_v4_service.updater.updater import ServiceUpdater, temporary_api_key

al_log.init_logging('updater.safelist')
classification = forge.get_classification()


LOGGER = logging.getLogger('assemblyline.updater.safelist')

UI_SERVER = os.getenv('UI_SERVER', 'https://nginx')
UPDATE_CONFIGURATION_PATH = os.environ.get('UPDATE_CONFIGURATION_PATH', "/tmp/safelist_updater_config.yaml")
UPDATE_OUTPUT_PATH = os.environ.get('UPDATE_OUTPUT_PATH', "/tmp/safelist_updater_output")
UPDATE_DIR = os.path.join(tempfile.gettempdir(), 'safelist_updates')

BLOCK_SIZE = 64 * 1024
HASH_LEN = 1000


class SkipSource(RuntimeError):
    pass


def add_cacert(cert: str):
    # Add certificate to requests
    cafile = certifi.where()
    with open(cafile, 'a') as ca_editor:
        ca_editor.write(f"\n{cert}")


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
        self.updater_type = "safelist"

    def do_local_update(self) -> None:
        old_update_time = self.get_local_update_time()
        run_time = time.time()
        output_directory = tempfile.mkdtemp()

        self.log.info("Setup service account.")
        username = self.ensure_service_account()
        self.log.info("Create temporary API key.")
        with temporary_api_key(self.datastore, username) as api_key:
            self.log.info(f"Connecting to Assemblyline API: {UI_SERVER}")
            al_client = get_client(UI_SERVER, apikey=(username, api_key), verify=False)

            # Check if new signatures have been added
            self.log.info("Check for new signatures.")
            if al_client.signature.update_available(
                    since=epoch_to_iso(old_update_time) or '', sig_type=self.updater_type)['update_available']:
                self.log.info("An update is available for download from the datastore")

                extracted_zip = False
                attempt = 0

                # Sometimes a zip file isn't always returned, will affect service's use of signature source. Patience..
                while not extracted_zip and attempt < 5:
                    temp_zip_file = os.path.join(output_directory, 'temp.zip')
                    al_client.signature.download(
                        output=temp_zip_file, query=f"type:{self.updater_type} AND (status:NOISY OR status:DEPLOYED)")

                    if os.path.exists(temp_zip_file):
                        try:
                            with ZipFile(temp_zip_file, 'r') as zip_f:
                                zip_f.extractall(output_directory)
                                extracted_zip = True
                                self.log.info("Zip extracted.")
                        except Exception:
                            attempt += 1
                            self.log.warning(f"[{attempt}/5] Bad zip. Trying again after 30s...")
                            time.sleep(30)

                        os.remove(temp_zip_file)

                if attempt == 5:
                    self.log.error("Signatures aren't saved to disk. Check sources..")
                    shutil.rmtree(output_directory, ignore_errors=True)
                else:
                    self.log.info("New ruleset successfully downloaded and ready to use")
                    self.serve_directory(output_directory)
                    self.set_local_update_time(run_time)

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
            source_default_classification = {}

            # Go through each source and download file
            for source_name, source_obj in sources.items():
                source = source_obj.as_primitives()
                uri: str = source['uri']
                cache_name = f"{source_name}.txt"
                source_default_classification[source_name] = source.get('default_classification',
                                                                        classification.UNRESTRICTED)
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
                except SkipSource:
                    if cache_name in previous_hashes:
                        files_sha256[cache_name] = previous_hashes[cache_name]
                    continue

                if os.path.exists(extracted_path) and os.path.isfile(extracted_path):
                    success = 0
                    with open(extracted_path) as fh:
                        reader = csv.reader(fh, delimiter=',', quotechar='"')
                        hash_list = []
                        for line in reader:
                            sha1, md5, _, filename, size = line[:5]
                            if sha1 == "SHA-1":
                                continue

                            data = {
                                "file": {"name": [filename], "size": size},
                                "hashes": {"md5": md5.lower(), "sha1": sha1.lower()},
                                "sources": [
                                    {"name": source['name'],
                                     'type': 'external',
                                     "reason": [f"Exist in source as {filename}"]}
                                ],
                                'type': "file"
                            }
                            hash_list.append(data)

                            if len(hash_list) % HASH_LEN == 0:
                                try:
                                    resp = client._connection.put("api/v4/safelist/add_update_many/", json=hash_list)
                                    success += resp['success']
                                except Exception as e:
                                    self.log.error(f"Failed to insert hash into safelist: {str(e)}")

                                hash_list = []

                    os.unlink(extracted_path)
                    self.log.info(f"Import finished. {success} hashes have been processed.")

        self.set_source_update_time(run_time)
        self.set_source_extra(files_sha256)
        self.set_active_config_hash(self.config_hash(service))
        self.local_update_flag.set()


if __name__ == '__main__':
    with SafelistUpdateServer() as server:
        server.serve_forever()
