import logging
import os
import threading
from collections import UserDict
from queue import Queue
from types import SimpleNamespace
from unittest import mock

import pytest
import requests

os.environ["SERVICE_MANIFEST_PATH"] = os.path.join(os.path.dirname(__file__), "..", "service_manifest.yml")

from assemblyline.odm.models.service import UpdateSource
from assemblyline_v4_service.updater.helper import SkipSource
from assemblyline_v4_service.updater.updater import SOURCE_STATUS_KEY

from safelist.update_server import SafelistUpdateServer, url_download

LOGGER = logging.getLogger("test")
SOURCE = {"name": "test", "uri": "https://example.com/hashes.txt"}


class FakeHash(UserDict):
    def set(self, key, value):
        self[key] = value


def response(status_code, reason=""):
    resp = mock.Mock(status_code=status_code, reason=reason, ok=200 <= status_code < 400, headers={}, content=b"")
    resp.iter_content.return_value = [b"data"]
    return resp


@pytest.fixture
def session():
    with mock.patch("safelist.update_server.requests.Session") as session_cls:
        session = session_cls.return_value
        session.head.return_value = response(200)
        yield session


def test_url_download_writes_file(session, tmp_path):
    session.get.return_value = response(200)

    path = url_download(SOURCE, None, LOGGER, str(tmp_path))

    assert path == os.path.join(tmp_path, "hashes.txt")
    with open(path, "rb") as f:
        assert f.read() == b"data"


def test_url_download_not_modified(session, tmp_path):
    session.get.return_value = response(304, "Not Modified")

    with pytest.raises(SkipSource):
        url_download(SOURCE, None, LOGGER, str(tmp_path))


@pytest.mark.parametrize("status_code,reason", [(404, "Not Found"), (410, "Gone"), (500, "Internal Server Error")])
def test_url_download_raises_on_unsuccessful_response(session, tmp_path, status_code, reason):
    session.get.return_value = response(status_code, reason)

    with pytest.raises(requests.HTTPError, match=f"Download not successful: {status_code} {reason}"):
        url_download(SOURCE, None, LOGGER, str(tmp_path))


def test_url_download_raises_on_connection_error(session, tmp_path):
    session.get.side_effect = requests.ConnectionError("connection refused")

    with pytest.raises(requests.ConnectionError, match="connection refused"):
        url_download(SOURCE, None, LOGGER, str(tmp_path))


def test_do_source_update_reports_http_error(session):
    session.get.return_value = response(404, "Not Found")
    source = UpdateSource(dict(SOURCE, pattern=".*"))

    server = SafelistUpdateServer.__new__(SafelistUpdateServer)
    server.log = LOGGER
    server.update_data_hash = FakeHash()
    server.update_queue = Queue()
    server.local_update_flag = threading.Event()
    server.config_hash = mock.Mock(return_value=0)
    server._service = SimpleNamespace(config={})
    server.update_queue.put(source.name)

    with (
        mock.patch("safelist.update_server.git_clone_repo", side_effect=Exception("not a git repository")),
        mock.patch("safelist.update_server.time.sleep"),
    ):
        server.do_source_update(SimpleNamespace(update_config=SimpleNamespace(sources=[source])))

    status = server.update_data_hash[f"{source.name}.{SOURCE_STATUS_KEY}"]
    assert status["state"] == "ERROR"
    assert status["message"] == "Download not successful: 404 Not Found"
