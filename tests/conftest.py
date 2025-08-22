import os
import subprocess
import tempfile

import port_for
import pytest
from pytest_redis import factories
from redis.client import Redis

file_dir = os.path.dirname(os.path.abspath(__file__))
dbpath = os.path.join(file_dir, "redisdata")
inmor_path = os.path.join(os.path.dirname(file_dir), "target/debug/inmor")


trdb = factories.redis_proc(port=6088, datadir=dbpath)

rdb = factories.redisdb("trdb")


@pytest.fixture(scope="function")
def loaddata(rdb: Redis) -> Redis:
    """Loads the test data into redis instance for testing."""
    redis = rdb
    with open(os.path.join(dbpath, "dump.data"), "rb") as f:
        data = f.read()
        # Now redis-cli against this
        _ = subprocess.run(["redis-cli", "-p", "6088", "--pipe"], input=data)
    return redis


@pytest.fixture(scope="session")
def start_server(trdb):
    """Starts the inmor rust application on a port and returns it."""
    port = port_for.get_port(None)
    with tempfile.TemporaryDirectory() as tmpdir:
        tconfig = os.path.join(tmpdir, "testconfig.toml")
        with open(tconfig, "w") as f:
            f.write(f'domain = "http://localhost:{port}"\n')
            f.write('redis_uri = "redis://localhost:6088"\n')
        # Now start a process
        inmor_proc = subprocess.Popen([inmor_path, "-p", str(port), "-c", tconfig])
        assert not inmor_proc.poll()
        yield port
        inmor_proc.terminate()
