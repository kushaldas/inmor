import httpx
from redis.client import Redis


def test_server(loaddata: Redis, start_server: int):
    "Checks redis"
    _rdb = loaddata
    port = start_server
    resp = httpx.get(f"http://localhost:{port}")
    assert resp.status_code == 200


def test_index_view(loaddata: Redis, start_server: int):
    "Tests index view of the server."
    _rdb = loaddata
    port = start_server
    resp = httpx.get(f"http://localhost:{port}")
    assert resp.status_code == 200
    assert resp.text == "Index page."


def test_trust_marked_list(loaddata: Redis, start_server: int):
    "Tests /trust_marked_list"
    _rdb = loaddata
    port = start_server
    url = f"http://localhost:{port}/trust_marked_list?trust_mark_type=https://sunet.se/does_not_exist_trustmark"
    resp = httpx.get(url)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 3
    subs = {
        "https://fakerp0.labb.sunet.se",
        "https://fakeop0.labb.sunet.se",
        "https://fakerp1.labb.sunet.se",
    }

    # make sure that the list of subordinates matches
    assert set(data) == subs
