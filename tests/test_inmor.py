import httpx
from redis.client import Redis


def test_server(loaddata: Redis, start_server: int):
    "Checks redis"
    _rdb = loaddata
    port = start_server
    resp = httpx.get(f"http://localhost:{port}")
    assert resp.status_code == 200


def test_index_view(loaddata: Redis, start_server: int):
    "Checks redis"
    _rdb = loaddata
    port = start_server
    resp = httpx.get(f"http://localhost:{port}")
    assert resp.status_code == 200
    assert resp.text == "Index page."
