import csv
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import time

import pycdlib
import requests
from assemblyline.common.digests import get_sha256_for_file
from assemblyline.common.str_utils import safe_str
from assemblyline.odm.models.service import Service, UpdateSource
from assemblyline_v4_service.updater.client import UpdaterClient
from assemblyline_v4_service.updater.helper import BLOCK_SIZE, SkipSource, add_cacert, git_clone_repo, urlparse
from assemblyline_v4_service.updater.updater import (
    SOURCE_UPDATE_ATTEMPT_DELAY_BASE,
    SOURCE_UPDATE_ATTEMPT_MAX_RETRY,
    ServiceUpdater,
    classification,
)

csv.field_size_limit(sys.maxsize)


def url_download(source, previous_update=None, logger=None, output_dir=None):
    """

    :param source:
    :param previous_update:
    :return:
    """
    name = source["name"]
    uri = source["uri"]
    pattern = source.get("pattern", None)
    username = source.get("username", None)
    password = source.get("password", None)
    ca_cert = source.get("ca_cert", None)
    ignore_ssl_errors = source.get("ssl_ignore_errors", False)
    auth = (username, password) if username and password else None

    proxy = source.get("proxy", None)
    headers_list = source.get("headers", [])
    headers = {}
    [headers.update({header["name"]: header["value"]}) for header in headers_list]

    logger.info(f"{name} source is configured to {'ignore SSL errors' if ignore_ssl_errors else 'verify SSL'}.")
    if ca_cert:
        logger.info("A CA certificate has been provided with this source.")
        add_cacert(ca_cert)

    # Create a requests session
    session = requests.Session()
    session.verify = not ignore_ssl_errors

    # Let https requests go through proxy
    proxies = {"http": proxy, "https": proxy} if proxy else None

    try:
        response = None
        with tempfile.NamedTemporaryFile("w") as private_key_file:
            if source.get("private_key"):
                logger.info("A private key has been provided with this source")
                private_key_file.write(source["private_key"])
                private_key_file.seek(0)
                session.cert = private_key_file.name

            # Check the response header for the last modified date
            response = session.head(uri, auth=auth, headers=headers, proxies=proxies)
            last_modified = response.headers.get("Last-Modified", None)
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
                    headers["If-Modified-Since"] = previous_update
                else:
                    headers = {"If-Modified-Since": previous_update}

            response = session.get(uri, auth=auth, headers=headers, proxies=proxies, stream=True)

        # Check the response code
        if response.status_code == requests.codes["not_modified"]:
            # File has not been modified since last update, do nothing
            raise SkipSource()
        elif response.ok:
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)

            file_name = os.path.basename(urlparse(uri).path)
            file_path = os.path.join(output_dir, file_name)
            with open(file_path, "wb") as f:
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
    logger.info(f"Extracting safelist file from {file}")
    dir = os.path.dirname(file)
    try:
        # Check if we're dealing with an NSRL ISO
        iso = pycdlib.PyCdlib()
        iso.open(file)
        iso.get_entry("/NSRLFILE.ZIP;1")
        del iso
        logger.info(f'{file} is an NSRL ISO. Extracting embedded "NSRLFile.txt.zip"..')

        # If we are, then we need to extract the embedded file as assign that as the 'true' file to be extracted
        zip_file = os.path.join(dir, "NSRLFile.txt.zip")
        subprocess.run(["7z", "x", "-y", file, f"-o{dir}", "NSRLFile.txt.zip"], capture_output=True)
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
    subprocess.run(["7z", "x", "-y", file, f"-o{dir}", pattern], capture_output=True)
    logger.info(f"Extraction complete: {safelist_file}")
    os.unlink(file)

    safe_distributors_list_regex = "|".join(safe_distributors_list) if safe_distributors_list else None
    try:
        if safelist_file.endswith(".db"):
            with tempfile.NamedTemporaryFile("w", delete=False) as csv:
                # Assume this is a NSRL SQL DB
                with sqlite3.connect(safelist_file) as db:
                    # Include expected header for CSV format
                    csv.write("SHA-256,SHA-1,MD5,Filename,Filesize\n")
                    package_filter = ""
                    if safe_distributors_list_regex:
                        # Retrieve the list of package_ids associated to each manufacturer
                        logger.info(
                            f"Retrieving package_ids that belong to the following distributor pattern: {safe_distributors_list_regex}"
                        )
                        package_ids = [
                            str(r[1])
                            for r in db.execute(
                                "SELECT MFG.name, PKG.package_id FROM PKG JOIN MFG USING (manufacturer_id)"
                            )
                            if re.match(safe_distributors_list_regex, r[0])
                        ]
                        package_filter = f"WHERE FILE.package_id IN ({', '.join(package_ids)})"
                    for r in db.execute(
                        f"SELECT DISTINCT FILE.sha256, FILE.sha1, FILE.md5, FILE.file_name, FILE.file_size FROM FILE {package_filter}"
                    ):
                        if not len(r) == 5:
                            # We're falling short of expectations, raise a warning about the row and continue
                            logger.warning(f"Expected 5 items but got: {r}. Skipping row..")
                            continue
                        csv.write(",".join([safe_str(i, force_str=True) for i in r]) + "\n")
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

    def import_update(self, file_path, source_name: str, *args, **kwargs):
        with open(file_path) as fh:
            reader = csv.reader(fh, delimiter=",", quotechar='"')
            hash_list = []

            def add_hash_set() -> int:
                try:
                    resp = self.client.safelist.add_update_many(hash_list)
                    return resp["success"]
                except Exception as e:
                    self.log.error(f"Failed to insert hash into safelist: {str(e)}")
                return 0

            for line in reader:
                try:
                    if len(line) == 5:
                        # No commas in filename
                        sha256, sha1, md5, filename, size = line[:5]
                    else:
                        # Commas found in filename, preserve this in safelist
                        sha256, sha1, md5 = line[:3]
                        filename = ",".join(line[3:-1])
                        size = line[-1]
                    if sha1 == "SHA-1":
                        # Assume this is a header for a CSV and move onto next line
                        continue

                    data = {
                        "file": {},
                        "hashes": {},
                        "sources": [{"name": source_name, "type": "external", "reason": ["Exists in source"]}],
                        "type": "file",
                    }
                    if md5:
                        data["hashes"]["md5"] = md5.lower()
                    if sha1:
                        data["hashes"]["sha1"] = sha1.lower()
                    if sha256:
                        data["hashes"]["sha256"] = sha256.lower()
                    if size:
                        data["file"]["size"] = size
                    if filename:
                        data["file"]["name"] = [filename]
                        data["sources"][0]["reason"] = [f"Exists in source as {filename}"]
                except Exception as e:
                    self.log.warning(
                        f"An error occurred while preparing safelisted metadata about a file using [{line}]: {e}. Skipping.."
                    )
                    continue

                hash_list.append(data)

        os.unlink(file_path)
        self.log.info(f"Import finished. {add_hash_set()} hashes have been processed.")

    def do_local_update(self) -> None:
        # No need to perform local updates, all service usage will be with service-server or directly with the datastore
        pass

    def do_source_update(self, service: Service) -> None:
        run_time = time.time()
        with tempfile.TemporaryDirectory() as update_dir:

            self.log.info("Connected!")

            # Parse updater configuration
            previous_hashes: dict[str, dict[str, str]] = self.get_source_extra()
            sources: dict[str, UpdateSource] = {_s["name"]: _s for _s in service.update_config.sources}
            files_sha256: dict[str, dict[str, str]] = {}

            # Map already visited URIs to download paths (avoid re-cloning/re-downloads)
            seen_fetches = dict()

            # Go through each source queued and download file
            while self.update_queue.qsize():
                update_attempt = -1
                source_name = self.update_queue.get()
                while update_attempt < SOURCE_UPDATE_ATTEMPT_MAX_RETRY:
                    # Introduce an exponential delay between each attempt
                    time.sleep(SOURCE_UPDATE_ATTEMPT_DELAY_BASE**update_attempt)
                    update_attempt += 1

                    # Set current source for pushing state to UI
                    self._current_source = source_name
                    source_obj = sources[source_name]
                    old_update_time = self.get_source_update_time()

                    self.push_status("UPDATING", "Starting..")
                    source = source_obj.as_primitives()
                    uri: str = source["uri"]
                    default_classification = source.get("default_classification", classification.UNRESTRICTED)

                    try:
                        self.push_status("UPDATING", "Pulling..")
                        output = None
                        seen_fetch = seen_fetches.get(uri)
                        if seen_fetch == "skipped":
                            # Skip source if another source says nothing has changed
                            raise SkipSource
                        elif seen_fetch and os.path.exists(seen_fetch):
                            # We've already fetched something from the same URI, re-use downloaded path
                            self.log.info(f"Already visited {uri} in this run. Using cached download path..")
                            output = seen_fetches[uri]
                        else:
                            # Pull sources from external locations (method depends on the URL)
                            try:
                                # First we'll attempt by performing a Git clone
                                # (since not all services hint at being a repository in their URL),
                                output = git_clone_repo(source, old_update_time, self.log, update_dir)
                            except SkipSource:
                                raise
                            except Exception as git_ex:
                                # Should that fail, we'll attempt a direct-download using Python Requests
                                if not uri.endswith(".git"):
                                    # Proceed with direct download, raise exception as required if necessary
                                    output = url_download(source, old_update_time, self.log, update_dir)
                                else:
                                    # Raise Git Exception
                                    raise git_ex
                            # Add output path to the list of seen fetches in this run
                            seen_fetches[uri] = output

                        file = extract_safelist(
                            output,
                            source["pattern"],
                            self.log,
                            self._service.config.get("trusted_distributors", []),
                        )

                        # Add to collection of sources for caching purposes
                        self.log.info(f"Found new {self.updater_type} rule files to process for {source_name}!")
                        previous_hashes[source_name] = {file: get_sha256_for_file(file)}
                        self.push_status("UPDATING", "Importing..")
                        # Import into Assemblyline
                        self.import_update(file, source_name, default_classification)
                        self.push_status("DONE", "Signature(s) Imported.")
                    except SkipSource:
                        # This source hasn't changed, no need to re-import into Assemblyline
                        self.log.info(f"No new {self.updater_type} rule files to process for {source_name}")
                        if source_name in previous_hashes:
                            files_sha256[source_name] = previous_hashes[source_name]
                        seen_fetches[uri] = "skipped"
                        self.push_status("DONE", "Skipped.")
                        break
                    except Exception as e:
                        # There was an issue with this source, report and continue to the next
                        self.log.error(f"Problem with {source['name']}: {e}")
                        self.push_status("ERROR", str(e))
                        continue

                    self.set_source_update_time(run_time)
                    self.set_source_extra(files_sha256)
                    break
        self.set_active_config_hash(self.config_hash(service))
        self.local_update_flag.set()


if __name__ == "__main__":
    with SafelistUpdateServer(default_pattern="*.txt") as server:
        server.serve_forever()
