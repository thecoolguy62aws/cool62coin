import time

from mine import Miner


def main():
    m = Miner()
    m2 = None
    try:
        candidate = {"index": 1, "transactions": [], "previous_hash": "0" * 64,
                     "miner": "minerA", "difficulty": 2}
        solved = m.solve(candidate)
        assert solved["difficulty"] == 2
        assert solved["hash"].startswith("00")
        assert solved["index"] == 1

        m2 = Miner()
        long = {"index": 2, "transactions": [], "previous_hash": "0" * 64,
                "miner": "minerA", "difficulty": 6}
        m2._conn.send(long)
        time.sleep(0.3)

        t0 = time.time()
        m2.shutdown()
        dt = time.time() - t0
        assert dt < 4, f"shutdown took {dt:.1f}s while grinding"
        assert m2._process is None or not m2._process.is_alive(), "worker still alive after shutdown"
        try:
            m2.solve(candidate)
            raise AssertionError("solve after shutdown must raise")
        except RuntimeError:
            pass

        m._process.terminate()
        m._process.join(timeout=1)
        assert not m._process.is_alive(), "test worker should be dead"

        solved2 = m.solve(candidate)
        assert solved2["index"] == 1
        assert solved2["hash"].startswith("00")
    finally:
        m.shutdown()
        if m2 is not None:
            m2.shutdown()

    print("MINER TESTS PASSED")


if __name__ == "__main__":
    main()