#!/usr/bin/env python3
"""Standalone mining client.

Polls a local node's GET /work endpoint for a block template, solves the
PoW, and submits the finished block via POST /block. Uses a GPU through
OpenCL when available (pyopencl + an OpenCL driver + numpy), otherwise
falls back to CPU worker processes. Prints live hashrate / ETA.

Usage:
    python miner.py                    # auto: GPU if present else CPU
    python miner.py --cpu --threads 4
    python miner.py --gpu --batch 2097152
"""

import argparse
import hashlib
import json
import math
import multiprocessing
import queue
import signal
import sys
import threading
import time

import requests

import config
from core import Block, load_key_address

DEFAULT_NODE = f"http://127.0.0.1:{config.INTERNAL_PORT}"
DEFAULT_BATCH = 1 << 20


# --------------------------------------------------------------------------
# work template fetch thread
# --------------------------------------------------------------------------

class WorkFetcher(threading.Thread):
    def __init__(self, node, interval):
        super().__init__(daemon=True)
        self.node = node
        self.interval = interval
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._snapshot = None

    def run(self):
        while not self._stop.is_set():
            try:
                data = requests.get(self.node + "/work", timeout=10).json()
                if data.get("success"):
                    with self._lock:
                        self._snapshot = (data.get("template_id"), data)
            except Exception:
                pass
            self._stop.wait(self.interval)

    def snapshot(self):
        with self._lock:
            return self._snapshot

    def stop(self):
        self._stop.set()


def build_candidate(work, miner_address):
    return {
        "index": work["index"],
        "transactions": work["transactions"],
        "previous_hash": work["previous_hash"],
        "miner": miner_address,
        "difficulty": work["difficulty"],
        "timestamp": work["timestamp"],
    }


# --------------------------------------------------------------------------
# CPU engine
# --------------------------------------------------------------------------

def _cpu_worker(candidate, worker_id, num_workers, stop, attempts, attempt_lock, result_q):
    try:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    except (ValueError, OSError):
        pass

    block = Block(
        index=candidate["index"],
        transactions=candidate["transactions"],
        previous_hash=candidate["previous_hash"],
        miner=candidate["miner"],
        difficulty=candidate["difficulty"],
        timestamp=candidate["timestamp"],
        nonce=worker_id,
    )
    local = 0

    def flush():
        nonlocal local
        with attempt_lock:
            attempts.value += local
        local = 0

    try:
        while not stop.is_set():
            if block.is_mined():
                flush()
                result_q.put({"ok": True, "block": block.to_dict()})
                return
            local += 1
            block.nonce += num_workers
            block.hash = block.calculate_hash()
            if local % 4096 == 0:
                flush()
    except BaseException:
        pass
    flush()
    result_q.put({"ok": False, "reason": "stopped"})


class CpuEngine:
    def __init__(self, candidate, threads):
        self.stop_evt = multiprocessing.Event()
        self.attempts = multiprocessing.Value("q", 0)
        self.attempt_lock = multiprocessing.Lock()
        self.result_q = multiprocessing.Queue()
        self.procs = [
            multiprocessing.Process(
                target=_cpu_worker,
                args=(candidate, i, threads, self.stop_evt,
                      self.attempts, self.attempt_lock, self.result_q),
                daemon=True,
            )
            for i in range(threads)
        ]
        for p in self.procs:
            p.start()

    @property
    def tried(self):
        return self.attempts.value

    def poll(self, timeout=1.0):
        try:
            res = self.result_q.get(timeout=timeout)
        except queue.Empty:
            return None
        return res.get("block") if res.get("ok") else None

    def stop(self):
        try:
            self.stop_evt.set()
            for p in self.procs:
                p.join(timeout=2)
            self.result_q.close()
            self.result_q.cancel_join_thread()
        except BaseException:
            pass


# --------------------------------------------------------------------------
# OpenCL GPU engine (optional)
# --------------------------------------------------------------------------

_KERNEL = r"""
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

__constant uint K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

__constant ulong POW10[20] = {
    1UL, 10UL, 100UL, 1000UL, 10000UL, 100000UL, 1000000UL, 10000000UL,
    100000000UL, 1000000000UL, 10000000000UL, 100000000000UL,
    1000000000000UL, 10000000000000UL, 100000000000000UL,
    1000000000000000UL, 10000000000000000UL, 100000000000000000UL,
    1000000000000000000UL, 10000000000000000000UL
};

inline uchar msg_byte(uint pos, ulong val, uint plen, uint digits, uint slen,
                      __global const uchar* pre, __global const uchar* suf)
{
    if (pos < plen)
        return pre[pos];
    pos -= plen;
    if (pos < digits) {
        ulong div = POW10[digits - 1 - pos];
        return (uchar)('0' + (val / div) % 10);
    }
    pos -= digits;
    return suf[pos];
}

int digest_passes(const uint h[8], __global const uint* tw)
{
    for (uint k = 0; k < 8; k++) {
        if (h[k] < tw[k]) return 1;
        if (h[k] > tw[k]) return 0;
    }
    return 0;
}

__kernel void sha256_search(
    __global const uchar* pre, uint plen,
    __global const uchar* suf, uint slen,
    uint digits, ulong start_val, uint seq_len,
    __global const uint* tw,
    __global uint* result,
    __global uint* dbg, uint dbg_on)
{
    uint gid = get_global_id(0);
    if (gid >= seq_len)
        return;

    ulong val = start_val + (ulong)gid;
    ulong mlen = (ulong)plen + (ulong)digits + (ulong)slen;
    ulong total_blocks = (mlen + 9 + 63) / 64;

    uint h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    uint h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    uint w[64];

    for (ulong tb = 0; tb < total_blocks; tb++) {
        for (uint i = 0; i < 16; i++) {
            uint wv = 0;
            ulong block_start = tb * 64 + i * 4;
            for (uint j = 0; j < 4; j++) {
                ulong pos = block_start + j;
                uchar b;
                if (pos < mlen) {
                    b = msg_byte((uint)pos, val, plen, digits, slen, pre, suf);
                } else if (pos == mlen) {
                    b = 0x80;
                } else {
                    ulong len_start = total_blocks * 64 - 8;
                    if (pos < len_start) {
                        b = 0;
                    } else {
                        ulong bits = mlen * 8;
                        uint off = (uint)(pos - len_start);
                        b = (uchar)((bits >> (56 - 8 * off)) & 0xff);
                    }
                }
                wv = (wv << 8) | b;
            }
            w[i] = wv;
        }
        for (uint i = 16; i < 64; i++) {
            uint s0 = ROTR(w[i - 15], 7) ^ ROTR(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint s1 = ROTR(w[i - 2], 17) ^ ROTR(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
        for (uint i = 0; i < 64; i++) {
            uint S1 = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);
            uint chh = (e & f) ^ ((~e) & g);
            uint t1 = h + S1 + chh + K256[i] + w[i];
            uint S0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
            uint maj = (a & b) ^ (a & c) ^ (b & c);
            uint t2 = S0 + maj;
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h0 += a; h1 += b; h2 += c; h3 += d; h4 += e; h5 += f; h6 += g; h7 += h;
    }

    if (dbg_on && gid == 0) {
        dbg[0] = h0; dbg[1] = h1; dbg[2] = h2; dbg[3] = h3;
        dbg[4] = h4; dbg[5] = h5; dbg[6] = h6; dbg[7] = h7;
    }

    uint H[8] = {h0, h1, h2, h3, h4, h5, h6, h7};
    if (digest_passes(H, tw)) {
        atomic_max(&result[0], 1u);
        atomic_min(&result[1], gid);
    }
}
"""


def build_message(candidate):
    body = {
        "index": candidate["index"],
        "timestamp": candidate["timestamp"],
        "transactions": candidate["transactions"],
        "previous_hash": candidate["previous_hash"],
        "miner": candidate["miner"],
    }
    s = json.dumps(body, sort_keys=True)
    idx = s.index('"previous_hash"')
    prefix = (s[:idx] + '"nonce": ').encode("ascii")
    suffix = s[idx - 2:].encode("ascii")
    return prefix, suffix


class GpuEngine:
    def __init__(self, candidate, batch_size):
        import pyopencl as cl
        import numpy as np

        self.cl = cl
        self.np = np
        self.batch_size = batch_size
        self.ctx = None
        for platform in cl.get_platforms():
            try:
                devices = platform.get_devices()
                if devices:
                    self.ctx = cl.Context(devices=[devices[0]])
                    break
            except cl.Error:
                continue
        if self.ctx is None:
            raise RuntimeError("no usable OpenCL platform")
        self.queue = cl.CommandQueue(self.ctx)
        try:
            self.device_name = self.ctx.devices[0].name
        except AttributeError:
            self.device_name = "unknown"

        self.prefix, self.suffix = build_message(candidate)
        self.candidate = candidate
        self.difficulty = candidate["difficulty"]
        target = (1 << 256) // self.difficulty
        tw_bytes = target.to_bytes(32, "big")
        self.tw = self.np.array(
            [int.from_bytes(tw_bytes[i:i + 4], "big") for i in range(0, 32, 4)],
            dtype=self.np.uint32,
        )
        self.target = target

        self.mf = cl.mem_flags
        self.pre_buf = cl.Buffer(
            self.ctx, self.mf.READ_ONLY | self.mf.COPY_HOST_PTR,
            hostbuf=self.prefix)
        self.suf_buf = cl.Buffer(
            self.ctx, self.mf.READ_ONLY | self.mf.COPY_HOST_PTR,
            hostbuf=self.suffix)
        self.program = cl.Program(self.ctx, _KERNEL).build()
        self.kernel = self.program.sha256_search
        self.tw_buf = cl.Buffer(
            self.ctx, self.mf.READ_ONLY | self.mf.COPY_HOST_PTR, hostbuf=self.tw)
        self.t0_buf = cl.Buffer(
            self.ctx, self.mf.READ_ONLY | self.mf.COPY_HOST_PTR,
            hostbuf=self.np.zeros(8, dtype=self.np.uint32))

        self._nonce = 0
        self._stop = False
        self.counter = 0

        self._verify_selftest()

    def _verify_selftest(self):
        for k in (0, 123456789):
            block = Block(
                index=self.candidate["index"],
                transactions=self.candidate["transactions"],
                previous_hash=self.candidate["previous_hash"],
                miner=self.candidate["miner"],
                difficulty=self.candidate["difficulty"],
                timestamp=self.candidate["timestamp"],
                nonce=k,
            )
            msg = self.prefix + str(k).encode("ascii") + self.suffix
            if hashlib.sha256(msg).hexdigest() != block.hash:
                raise RuntimeError(
                    "GPU message layout does not match Block.calculate_hash")
        nonce = 123456789
        digits = len(str(nonce))
        dbg = self.cl.Buffer(self.ctx, self.mf.READ_WRITE, 32)
        result = self.cl.Buffer(self.ctx, self.mf.READ_WRITE, 8)
        self._write_u32s(result, (0, 0xFFFFFFFF))
        np = self.np
        self.kernel(
            self.queue, (1,), None,
            self.pre_buf, np.uint32(len(self.prefix)),
            self.suf_buf, np.uint32(len(self.suffix)),
            np.uint32(digits), np.uint64(nonce), np.uint32(1),
            self.t0_buf,          # target 0 -> self-test cannot hit
            result, dbg, np.uint32(1),
        )
        self.queue.finish()
        got = b"".join(int(w).to_bytes(4, "big") for w in self._read_u32s(dbg, 8))
        expected = hashlib.sha256(
            self.prefix + str(nonce).encode("ascii") + self.suffix).digest()
        if got != expected:
            raise RuntimeError("OpenCL kernel self-test failed; refusing GPU mining")
        if int(self._read_u32s(result, 2)[0]) != 0:
            raise RuntimeError("OpenCL self-test reported a false positive")

    def _write_u32s(self, buffer, values):
        self.cl.enqueue_copy(
            self.queue, buffer,
            self.np.array(values, dtype=self.np.uint32))

    def _read_u32s(self, buffer, count):
        host = self.np.empty(count, dtype=self.np.uint32)
        self.cl.enqueue_copy(self.queue, host, buffer)
        return host

    @property
    def tried(self):
        return self.counter

    def _launch_batch(self):
        if self._nonce > 10 ** 15:
            print("\nnonce space exhausted; restarting from 0")
            self._nonce = 0
        n = self._nonce
        digits = len(str(n))
        window = 10 ** digits - n
        seq = min(window, self.batch_size)
        start = n
        self._nonce += seq
        self.counter += seq

        result = self.cl.Buffer(self.ctx, self.mf.READ_WRITE, 8)
        self._write_u32s(result, (0, 0xFFFFFFFF))
        np = self.np
        self.kernel(
            self.queue, (seq,), None,
            self.pre_buf, np.uint32(len(self.prefix)),
            self.suf_buf, np.uint32(len(self.suffix)),
            np.uint32(digits), np.uint64(start), np.uint32(seq),
            self.tw_buf,
            result, None, np.uint32(0),
        )
        return start, seq, result

    def poll(self, timeout=1.0):
        deadline = time.monotonic() + timeout
        while not self._stop and time.monotonic() < deadline:
            start, seq, result = self._launch_batch()
            self.queue.finish()
            head, idx = (int(x) for x in self._read_u32s(result, 2))
            if head:
                return self._confirm(start, seq, idx)
        return None

    def _confirm(self, start, seq, idx):
        nonce = start + idx
        if nonce < start or nonce >= start + seq:
            return None
        msg = self.prefix + str(nonce).encode("ascii") + self.suffix
        digest = hashlib.sha256(msg).hexdigest()
        if not int(digest, 16) < self.target:
            print("\nGPU produced a bad nonce; searching CPU range...")
            for k in range(seq):
                n = start + k
                if int(hashlib.sha256(
                        self.prefix + str(n).encode("ascii") + self.suffix
                ).hexdigest(), 16) < self.target:
                    return self._block_for(n)
            return None
        return self._block_for(nonce)

    def _block_for(self, nonce):
        block = dict(self.candidate)
        block["nonce"] = nonce
        block["hash"] = hashlib.sha256(
            self.prefix + str(nonce).encode("ascii") + self.suffix).hexdigest()
        return block

    def stop(self):
        self._stop = True


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def fmt_hashrate(h):
    if not math.isfinite(h) or h <= 0:
        return "--"
    for unit in ("", "K", "M", "G", "T"):
        if h < 1000:
            return f"{h:,.1f}{unit}"
        h /= 1000
    return f"{h:,.1f}P"


def fmt_eta(seconds):
    if not math.isfinite(seconds):
        return "--:--:--"
    s = max(0, int(seconds))
    return f"{s // 3600:02d}:{(s % 3600) // 60:02d}:{s % 60:02d}"


def submit(node, block):
    try:
        r = requests.post(node + "/block", json=block, timeout=20)
        data = r.json()
        if data.get("success"):
            return True
        print(f"\n  rejected by node: {data.get('error', 'unknown')}")
        return False
    except Exception as e:
        print(f"\n  submit failed: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(description="Standalone blockchain miner")
    parser.add_argument("--node", default=DEFAULT_NODE, help="local node base URL")
    parser.add_argument("--miner", default=None,
                        help="reward address (default: local node identity)")
    parser.add_argument("--threads", type=int, default=os_cpu_count(),
                        help="CPU worker count (default: cpu_count)")
    parser.add_argument("--interval", type=float, default=3.0,
                        help="/work poll interval in seconds")
    parser.add_argument("--batch", type=int, default=DEFAULT_BATCH,
                        help="GPU work-items per launch")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--gpu", action="store_true", help="force OpenCL GPU")
    mode.add_argument("--cpu", action="store_true", help="force CPU processes")
    args = parser.parse_args()

    if args.miner:
        miner_address = args.miner
    else:
        try:
            miner_address = load_key_address()
        except Exception:
            print("no public_key.pem found and --miner not given; aborting")
            return

    gpu_available = False
    if not args.cpu:
        try:
            import pyopencl  # noqa: F401
            gpu_available = True
        except ImportError:
            print("pyopencl not installed; using CPU. "
                  "Install with: pip install pyopencl")

    fetcher = WorkFetcher(args.node, args.interval)
    fetcher.start()
    engine = None
    active_key = None
    ignore_tid = None
    t0 = None
    last_stat = time.monotonic()
    shown_work = None

    try:
        while True:
            snap = fetcher.snapshot()
            tid = snap[0] if snap else None
            work = snap[1] if snap else None
            if ignore_tid is not None and tid is not None and tid != ignore_tid:
                ignore_tid = None
            need = bool(work and work.get("pending") and work.get("transactions"))
            if tid == ignore_tid:
                need = False
            work_key = None
            if work is not None:
                work_key = (work.get("index"), work.get("previous_hash"),
                            work.get("difficulty"))

            if engine is not None and work_key != active_key:
                print("\n  chain state changed; rebasing to the new tip")
                engine.stop()
                engine = None
                active_key = None
                t0 = None

            if engine is None and need:
                candidate = build_candidate(work, miner_address)
                shown_work = candidate
                print(f"Mining block #{candidate['index']} "
                      f"difficulty={candidate['difficulty']} "
                      f"txs={len(candidate['transactions'])}")
                if gpu_available and not args.cpu:
                    try:
                        engine = GpuEngine(candidate, args.batch)
                        print(f"  engine: OpenCL GPU ({engine.device_name})")
                    except Exception as e:
                        if args.gpu:
                            print(f"  GPU failed ({e}); aborting")
                            return
                        print(f"  GPU unavailable ({e}); using CPU")
                        engine = CpuEngine(candidate, args.threads)
                        print(f"  engine: CPU x{args.threads}")
                else:
                    engine = CpuEngine(candidate, args.threads)
                    print(f"  engine: CPU x{args.threads}")
                active_key = work_key
                t0 = time.monotonic()
                last_stat = time.monotonic()

            if engine is None:
                time.sleep(0.2)
                continue

            block = engine.poll(1.0)
            if block:
                result = submit(args.node, block)
                print(f"  nonce={block['nonce']:,} hash={block['hash'][:16]}..."
                      f" accepted={result}")
                engine.stop()
                engine = None
                active_key = None
                t0 = None
                if result is not None:
                    ignore_tid = tid
                time.sleep(1.0)
                continue

            now = time.monotonic()
            if t0 and now - last_stat >= 1.0:
                dt = max(now - t0, 1e-9)
                rate = engine.tried / dt
                eta = shown_work["difficulty"] / rate if rate > 0 else float("inf")
                line = (f"\r[{time.strftime('%H:%M:%S')}] {fmt_hashrate(rate)}/s "
                        f" target {shown_work['difficulty']} "
                        f" ETA {fmt_eta(eta)} nonces {engine.tried:,}")
                sys.stdout.write(line)
                sys.stdout.flush()
                last_stat = now
    except KeyboardInterrupt:
        print("\nminer stopped")
    finally:
        if engine is not None:
            try:
                engine.stop()
            except BaseException:
                pass
        fetcher.stop()


def os_cpu_count():
    return multiprocessing.cpu_count()


if __name__ == "__main__":
    main()