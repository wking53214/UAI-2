"""A throwaway PostgreSQL cluster for tests: the REAL server, started by the test, on a private port, in a private directory.

Nothing here is a mock. If the server binaries are not installed the tests FAIL with a message that says what to install;
they do not skip. Runs as the current user, or through `su postgres` when the test process is root (PostgreSQL refuses to
run as root).
"""

from __future__ import annotations

import glob
import os
import pwd
import shlex
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import List, Optional


def bindir() -> str:
    found = shutil.which("pg_ctl")
    if found:
        return str(Path(found).parent)
    candidates = sorted(glob.glob("/usr/lib/postgresql/*/bin/pg_ctl"), reverse=True)
    assert candidates, "PostgreSQL server binaries are not installed (need initdb and pg_ctl): apt-get install postgresql"
    return str(Path(candidates[0]).parent)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class Cluster:
    def __init__(self, *, config: Optional[List[str]] = None, hba_replication: bool = False) -> None:
        self.bin, self.port = bindir(), free_port()
        self.dir = tempfile.mkdtemp(prefix="uai-pg-")
        self.sock = tempfile.mkdtemp(prefix="uai-pgs-")
        self._root = os.geteuid() == 0
        if self._root:
            owner = pwd.getpwnam("postgres")
            for d in (self.dir, self.sock):
                os.chown(d, owner.pw_uid, owner.pw_gid)
        self._extra = config or []
        self._hba = hba_replication
        self._run(f"{self.bin}/initdb -D {self.dir} -A trust -U postgres")
        conf = Path(self.dir, "postgresql.conf")
        with conf.open("a") as fh:
            fh.write(f"\nport = {self.port}\nlisten_addresses = '127.0.0.1'\nunix_socket_directories = '{self.sock}'\n"
                     "fsync = on\nsynchronous_commit = on\n" + "\n".join(self._extra) + "\n")
        if hba_replication:
            Path(self.dir, "pg_hba.conf").open("a").write("host replication all 127.0.0.1/32 trust\n")

    def _run(self, cmd: str, check: bool = True) -> subprocess.CompletedProcess:  # type: ignore[type-arg]
        if self._root:
            cmd = f"su postgres -c {shlex.quote(cmd)}"
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, check=check)

    def start(self) -> "Cluster":
        self._run(f"{self.bin}/pg_ctl -D {self.dir} -l {self.dir}/log -w -t 30 start")
        return self

    def stop(self, mode: str = "fast") -> None:
        self._run(f"{self.bin}/pg_ctl -D {self.dir} -m {mode} -w stop", check=False)

    def kill(self) -> None:
        self._run(f"{self.bin}/pg_ctl -D {self.dir} -m immediate -w stop", check=False)

    @property
    def dsn(self) -> str:
        return f"host=127.0.0.1 port={self.port} user=postgres dbname=postgres"

    def dsn_via(self, port: int) -> str:
        return f"host=127.0.0.1 port={port} user=postgres dbname=postgres"

    def cleanup(self) -> None:
        self.kill()
        shutil.rmtree(self.dir, ignore_errors=True)
        shutil.rmtree(self.sock, ignore_errors=True)

    def wait_ready(self, timeout: float = 20) -> None:
        end = time.time() + timeout
        while time.time() < end:
            if self._run(f"{self.bin}/pg_isready -h 127.0.0.1 -p {self.port}", check=False).returncode == 0:
                return
            time.sleep(0.2)
        raise AssertionError("PostgreSQL did not become ready")


def make_standby(primary: "Cluster", via_port: int, *, application_name: str = "standby1") -> "Cluster":
    """A streaming standby of `primary`, whose WAL stream goes through 127.0.0.1:`via_port` (a proxy that can be told to drop
    traffic). A real second server, started with pg_basebackup, not a simulation."""
    c = Cluster.__new__(Cluster)
    c.bin, c.port = primary.bin, free_port()
    c.dir, c.sock = tempfile.mkdtemp(prefix="uai-pgsb-"), tempfile.mkdtemp(prefix="uai-pgss-")
    c._root, c._extra, c._hba = primary._root, [], False
    if c._root:
        owner = pwd.getpwnam("postgres")
        for d in (c.dir, c.sock):
            os.chown(d, owner.pw_uid, owner.pw_gid)
    os.chmod(c.dir, 0o700)
    c._run(f"{c.bin}/pg_basebackup -D {c.dir} -d 'host=127.0.0.1 port={via_port} user=postgres application_name={application_name}' "
           "-R -X stream -c fast")
    with Path(c.dir, "postgresql.conf").open("a") as fh:
        fh.write(f"\nport = {c.port}\nlisten_addresses = '127.0.0.1'\nunix_socket_directories = '{c.sock}'\n")
    return c


def promote(c: "Cluster") -> None:
    c._run(f"{c.bin}/pg_ctl -D {c.dir} -w promote")
