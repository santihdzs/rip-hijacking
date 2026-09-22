"""newline-delimited JSON message protocol for the master-worker cracker.

each message is one json object terminated by '\n'. explicit message types:

  worker -> master
    HELLO      {worker, host, pid, cores}   announce + join
    REQUEST    {}                            ask for a keyspace chunk
    PROGRESS   {chunk, tried, rate}          periodic progress (== heartbeat)
    HEARTBEAT  {}                            liveness while between chunks
    DONE       {chunk, tried}                chunk exhausted, no match
    FOUND      {chunk, key, idx}             key match

  master -> worker
    PARAMS     {data, digest, alphabet, length, construction, keyspace, chunk_size}
    ASSIGN     {chunk, start, end}           here is your chunk
    NOWORK     {}                            nothing free right now, retry
    STOP       {key, by}                     global halt (found or exhausted)
"""
import json
import select


def send_msg(sock, obj: dict):
    sock.sendall((json.dumps(obj) + "\n").encode())


class MsgReader:
    """buffered newline-delimited json reader over a blocking socket."""

    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def _fill_until_newline(self):
        while b"\n" not in self.buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                return False
            self.buf += chunk
        return True

    def read(self):
        """block for the next message; return dict or None on EOF."""
        if not self._fill_until_newline():
            return None
        line, self.buf = self.buf.split(b"\n", 1)
        line = line.strip()
        if not line:
            return self.read()
        return json.loads(line)

    def poll(self, timeout=0.0):
        """non-blocking: return a message if one is ready, else None.

        used by workers to notice a STOP without blocking the crack loop.
        """
        if b"\n" in self.buf:
            line, self.buf = self.buf.split(b"\n", 1)
            line = line.strip()
            return json.loads(line) if line else None
        r, _, _ = select.select([self.sock], [], [], timeout)
        if not r:
            return None
        chunk = self.sock.recv(65536)
        if not chunk:
            return {"type": "EOF"}
        self.buf += chunk
        if b"\n" in self.buf:
            line, self.buf = self.buf.split(b"\n", 1)
            line = line.strip()
            return json.loads(line) if line else None
        return None
