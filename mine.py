import multiprocessing as mp
import signal

import core


def _worker_loop(conn):
    try:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    except (ValueError, OSError):
        pass
    while True:
        try:
            candidate = conn.recv()
        except (EOFError, OSError, KeyboardInterrupt):
            return
        if candidate is None:
            return
        try:
            conn.send(("ok", core.solve_block(candidate)))
        except KeyboardInterrupt:
            return
        except Exception as exc:
            conn.send(("err", repr(exc)))


class Miner:
    def __init__(self):
        self._conn = None
        self._process = None
        self._closed = False
        self.start()

    def start(self):
        if self._closed:
            raise RuntimeError("miner is shut down")
        parent, child = mp.Pipe(duplex=True)
        self._process = mp.Process(target=_worker_loop, args=(child,), daemon=True)
        self._process.start()
        child.close()
        self._conn = parent

    def restart(self):
        if self._closed:
            raise RuntimeError("miner is shut down")
        self._kill_process()
        self.start()

    def solve(self, candidate):
        if self._closed:
            raise RuntimeError("miner is shut down")
        for _ in range(2):
            if self._process is None or not self._process.is_alive():
                self.restart()
            self._conn.send(candidate)
            while True:
                if self._conn.poll(0.5):
                    tag, payload = self._conn.recv()
                    if tag == "err":
                        raise RuntimeError(payload)
                    return payload
                if not self._process.is_alive():
                    break
        raise RuntimeError("miner worker failed repeatedly")

    def _kill_process(self):
        if self._process is not None:
            if self._process.is_alive():
                self._process.terminate()
            try:
                self._process.join(timeout=2)
            except Exception:
                pass
            self._process = None
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def shutdown(self):
        if self._closed:
            return
        self._closed = True
        if self._process is not None and self._process.is_alive():
            try:
                self._conn.send(None)
                self._process.join(timeout=1)
            except Exception:
                pass
        self._kill_process()