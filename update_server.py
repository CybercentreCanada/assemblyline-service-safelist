import csv
import math
import os
import pycdlib
import re
import requests
import sqlite3
import subprocess
import tempfile
import time

from assemblyline.common.digests import get_sha256_for_file
from assemblyline.odm.models.service import Service, UpdateSource
from assemblyline_client import get_client, Client
from assemblyline_v4_service.updater.updater import ServiceUpdater, temporary_api_key
from assemblyline_v4_service.updater.helper import add_cacert, BLOCK_SIZE, SkipSource, urlparse

from datetime import datetime


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


def extract_safelist(file, pattern, logger, safe_distributors_list=[]):
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

    safe_distributors_list_regex = '|'.join(safe_distributors_list) if safe_distributors_list else None
    try:
        if safelist_file.endswith('.db'):
            with tempfile.NamedTemporaryFile('w', delete=False) as csv:
                # Assume this is a NSRL SQL DB
                with sqlite3.connect(safelist_file) as db:
                    # Include expected header for CSV format
                    csv.write("SHA-256,SHA-1,MD5,Filename,Filesize\n")
                    package_filter = ""
                    if safe_distributors_list_regex:
                        # Retrieve the list of package_ids associated to each manufacturer
                        logger.info(f'Retrieving package_ids that belong to the following distributor pattern: {safe_distributors_list_regex}')
                        package_ids = [str(r[1]) for r in db.execute("SELECT MFG.name, PKG.package_id FROM PKG JOIN MFG USING (manufacturer_id)") if re.match(safe_distributors_list_regex, r[0])]
                        package_filter = f"WHERE FILE.package_id IN ({', '.join(package_ids)})"
                    for r in db.execute(f"SELECT DISTINCT FILE.sha256, FILE.sha1, FILE.md5, FILE.file_name, FILE.file_size FROM FILE {package_filter}"):
                        csv.write(','.join([str(i).strip() for i in r]) + "\n")
                csv.flush()
                os.unlink(safelist_file)
                safelist_file = csv.name
    except Exception:
        os.unlink(safelist_file)
        raise

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
                if len(line) == 5:
                    # No commas in filename
                    sha256, sha1, md5, filename, size = line[:5]
                else:
                    # Commas found in filename, preserve this in safelist
                    sha256, sha1, md5 = line[:3]
                    filename = ','.join(line[3:-1])
                    size = line[-1]
                if sha1 == "SHA-1":
                    # Assume this is a header for a CSV and move onto next line
                    continue

                data = {
                    "file": {},
                    "hashes": {},
                    "sources": [
                        {"name": source_name,
                            'type': 'external',
                            "reason": ["Exists in source"]}
                    ],
                    'type': "file"
                }
                if md5:
                    data['hashes']['md5'] = md5.lower()
                if sha1:
                    data['hashes']['sha1'] = sha1.lower()
                if sha256:
                    data['hashes']['sha256'] = sha256.lower()
                if size:
                    data['file']['size'] = size
                if filename:
                    data['file']['name'] = [filename]
                    data['sources'][0]['reason'] = [f"Exists in source as {filename}"]

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

                if "${QUARTERLY}" in uri:
                    y, m = datetime.now().strftime("%Y.%m").split('.')
                    d = 1
                    m = "%02d" % (math.floor(float(int(m)/3))*3)
                    source['uri'] = source['uri'].replace("${QUARTERLY}", f"{y}.{m}.{d}")
                    source['pattern'] = source['pattern'].replace("${QUARTERLY}", f"{y}.{m}.{d}")

                with tempfile.TemporaryDirectory() as update_dir:
                    try:
                        self.push_status("UPDATING", "Pulling..")
                        # Pull sources from external locations (method depends on the URL)
                        file = url_download(source=source, previous_update=old_update_time, logger=self.log,
                                            output_dir=update_dir)

                        file = extract_safelist(file, source['pattern'], self.log,
                                                self._service.config.get('trusted_distributors', []))
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
