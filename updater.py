# This updater is made to follow the NSRL file format which is a CSV file with the following format:
# "SHA-1","MD5","CRC32","FileName","FileSize","ProductCode","OpSystemCode","SpecialCode"
#
# NOTE: The only field we car about is the SHA1 the others are ignored
# You can then create your own safelist set that matches that format to have your own set of hashes...

import certifi
import csv
import json
import logging
import os
import pycdlib
import requests
import shutil
import tempfile
import time
import yaml
import zipfile

from assemblyline.common import log
from assemblyline.common.isotime import iso_to_epoch

from assemblyline_client import get_client

UPDATE_CONFIGURATION_PATH = os.environ.get('UPDATE_CONFIGURATION_PATH', "/tmp/safelist_updater_config.yaml")
UPDATE_OUTPUT_PATH = os.environ.get('UPDATE_OUTPUT_PATH', "/tmp/safelist_updater_output")

BLOCK_SIZE = 64 * 1024
HASH_LEN = 1000


def add_cacert(cert: str):
    # Add certificate to requests
    cafile = certifi.where()
    with open(cafile, 'a') as ca_editor:
        ca_editor.write(f"\n{cert}")


def url_download(source, target_path, cur_logger, previous_update=None):
    uri = source['uri']
    username = source.get('username', None)
    password = source.get('password', None)
    ca_cert = source.get('ca_cert', None)
    ignore_ssl_errors = source.get('ssl_ignore_errors', False)
    auth = (username, password) if username and password else None

    proxy = source.get('proxy', None)
    headers = source.get('headers', None)

    cur_logger.info(f"This source is configured to {'ignore SSL errors' if ignore_ssl_errors else 'verify SSL'}.")
    if ca_cert:
        cur_logger.info("A CA certificate has been provided with this source.")
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
                cur_logger.info("The file has not been modified since last run, skipping...")
                return False

        if previous_update:
            previous_update = time.strftime("%a, %d %b %Y %H:%M:%S %Z", time.gmtime(previous_update))
            if headers:
                headers['If-Modified-Since'] = previous_update
            else:
                headers = {'If-Modified-Since': previous_update}

        cur_logger.info(f"Downloading file from: {source['uri']}")
        with session.get(uri, auth=auth, headers=headers, stream=True) as response:
            # Check the response code
            if response.status_code == requests.codes['not_modified']:
                # File has not been modified since last update, do nothing
                cur_logger.info("The file has not been modified since last run, skipping...")
                return False
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
        cur_logger.info(str(e))
        return False
    finally:
        # Close the requests session
        session.close()


def download_extract_zip(cur_logger, source, target_path, extracted_path, working_directory, previous_update):
    if url_download(source, target_path, cur_logger, previous_update=previous_update):
        cur_logger.info(f"Unzipping downloaded file {target_path}... into {extracted_path}")

        with zipfile.ZipFile(target_path) as z:
            z.extract(source['pattern'], working_directory)
        os.unlink(target_path)

        os.rename(os.path.join(working_directory, source['pattern']), extracted_path)
        cur_logger.info(f"Unzip finished, created file {extracted_path}")


def download_extract_iso(cur_logger, source, target_path, extracted_path, working_directory, previous_update):
    # NSRL ISO only!
    if url_download(source, target_path, cur_logger, previous_update=previous_update):
        zip_file = f"{target_path}.zip"

        iso = pycdlib.PyCdlib()
        iso.open(target_path)

        cur_logger.info("Extracting NSRLFILE.ZIP form ISO...")
        with open(zip_file, "wb") as zip_fh:
            iso.get_file_from_iso_fp(zip_fh, iso_path='/NSRLFILE.ZIP;1')
        iso.close()
        os.unlink(target_path)

        cur_logger.info(f"Unzipping {zip_file} ...")
        with zipfile.ZipFile(zip_file) as z:
            z.extract(source['pattern'], working_directory)
        os.unlink(zip_file)

        os.rename(os.path.join(working_directory, source['pattern']), extracted_path)
        cur_logger.info(f"Unzip finished, created file {extracted_path}")


def update(client, cur_logger, working_directory, source, previous_update, previous_hash):

    cur_logger.info(f"Processing source: {source['name'].upper()}")
    download_name = os.path.basename(source['uri'])
    target_path = os.path.join(working_directory, 'dl', download_name)
    extracted_path = os.path.join(working_directory, source['name'])

    if download_name.endswith(".zip"):
        download_extract_zip(cur_logger, source, target_path,
                             extracted_path, working_directory, previous_update)
    elif download_name.endswith(".iso"):
        download_extract_iso(cur_logger, source, target_path,
                             extracted_path, working_directory, previous_update)
    else:
        url_download(source, extracted_path, cur_logger, previous_update=previous_update)

    if os.path.exists(extracted_path) and os.path.isfile(extracted_path):
        success = 0
        with open(extracted_path) as fh:
            reader = csv.reader(fh, delimiter=',', quotechar='"')
            hash_list = []
            for line in reader:
                sha1, md5, _, filename, size = line[:5]
                if sha1 == "SHA-1":
                    continue

                data = {"fileinfo": {"md5": md5.lower(), "sha1": sha1.lower(), "size": size, }, "sources": [
                    {"name": source['name'], 'type': 'external', "reason": [f"Exist in source as {filename}"]}]}
                hash_list.append(data)

                if len(hash_list) % HASH_LEN == 0:
                    try:
                        resp = client._connection.put("api/v4/safelist/add_update_many/", json=hash_list)
                        success += resp['success']
                    except Exception as e:
                        cur_logger.error(f"Failed to insert hash into safelist: {str(e)}")

                    hash_list = []

        os.unlink(extracted_path)
        cur_logger.info(f"Import finished. {success} hashes have been processed.")


def run_updater(cur_logger, update_config_path, update_output_path):
    # Setup working directory
    working_directory = os.path.join(tempfile.gettempdir(), 'safelist_updates')
    shutil.rmtree(working_directory, ignore_errors=True)
    os.makedirs(os.path.join(working_directory, 'dl'), exist_ok=True)
    os.makedirs(update_output_path, exist_ok=True)

    update_config = {}
    if update_config_path and os.path.exists(update_config_path):
        with open(update_config_path, 'r') as yml_fh:
            update_config = yaml.safe_load(yml_fh)
    else:
        cur_logger.error(f"Update configuration file doesn't exist: {update_config_path}")
        exit()

    # Exit if no update sources given
    if 'sources' not in update_config.keys() or not update_config['sources']:
        cur_logger.error("Update configuration does not contain any source to update from")
        exit()

    cur_logger.info(f"Connecting Assemblyline client to {update_config['ui_server']} ...")
    client = get_client(update_config['ui_server'], apikey=(
        update_config['api_user'], update_config['api_key']), verify=False)

    previous_update = update_config.get('previous_update', None)
    previous_hash = json.loads(update_config.get('previous_hash', None) or "{}")

    for source in update_config['sources']:
        update(client, cur_logger, working_directory, source, previous_update, previous_hash)

    # Create the response yaml
    with open(os.path.join(update_output_path, 'response.yaml'), 'w') as yml_fh:
        yaml.safe_dump(dict(hash="updated"), yml_fh)
    cur_logger.info("Done!")


if __name__ == "__main__":
    log.init_logging('updater.safelist')
    logger = logging.getLogger('assemblyline.updater.safelist')
    run_updater(logger, UPDATE_CONFIGURATION_PATH, UPDATE_OUTPUT_PATH)
