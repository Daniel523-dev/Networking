import os
import queue
import hmac
import zmq
import threading
import Encryption
HANDSHAKE_EID = b"__HANDSHAKE__"
MAX_QUEUE_BYTES = 256 * 1024 * 1024
def create_auth_keys(d, n):
    os.makedirs(d, exist_ok=True)
    [os.remove(os.path.join(d, f)) for f in os.listdir(d) if os.path.isfile(os.path.join(d, f)) and not f.endswith(('.prv', '.pub'))]
    stems = {os.path.splitext(f)[0] for f in os.listdir(d) if f.endswith(('.prv', '.pub'))}
    pairs = []
    for s in stems:
        prv, pub = os.path.join(d, s + '.prv'), os.path.join(d, s + '.pub')
        if os.path.isfile(prv) and os.path.isfile(pub):
            try:
                with open(prv, 'rb') as f:p_bytes = f.read()
                with open(pub, 'rb') as f:b_bytes = f.read()
                tk = Encryption.gen_x25519(True)
                if Encryption.shared_secret(tk[0], b_bytes) == Encryption.shared_secret(p_bytes, tk[1]):
                    pairs.append((prv, pub))
                    continue
            except Exception:pass
        for p in (prv, pub):
            if os.path.exists(p):os.remove(p)
    while len(pairs) < n:
        try:
            prv_b, pub_b = Encryption.gen_x25519(True)
            fid = os.urandom(64).hex()
            prv, pub = os.path.join(d, fid + '.prv'), os.path.join(d, fid + '.pub')
            with open(prv, 'wb') as f:f.write(prv_b)
            with open(pub, 'wb') as f:f.write(pub_b)
            pairs.append((prv, pub))
        except Exception:break
    return pairs
class ProtocolError(Exception):pass
class TCPServer:
    def __init__(self, host, port, auth_key_dir="./keys", keys=64, on_exchange=None):
        create_auth_keys(auth_key_dir, keys)
        self.auth_key_dir, self.on_exchange = auth_key_dir, on_exchange
        self.context = zmq.Context()
        self.sock = self.context.socket(zmq.ROUTER)
        self.sock.bind(f"tcp://{host}:{port}")
        self._eid_map, self._keys, self._handshakes, self._counters = {}, {}, {}, {}
        self._q_bytes = {}
        self._seen_eids = {}
        self._send_q = queue.Queue()
        self._lock, self._running = threading.Lock(), True
        self._io_thread = threading.Thread(target=self._loop, daemon=True)
        self._io_thread.start()
    def _hs_worker(self, cid, client_temp_pub):
        try:
            tk = Encryption.gen_x25519(True)
            self._send_q.put((cid, HANDSHAKE_EID, tk[1]))
            tss = Encryption.shared_secret(tk[0], client_temp_pub)
            _hash = Encryption.decryptGCM(self._handshakes[cid].get(timeout=5), tss)
            auth_file = ""
            if os.path.exists(self.auth_key_dir):
                for x in os.listdir(self.auth_key_dir):
                    if x.endswith(".pub") and hmac.compare_digest(_hash, Encryption.basic_kdf(open(os.path.join(self.auth_key_dir, x), "rb").read(), b'', 6)):
                        auth_file = os.path.join(self.auth_key_dir, x)
            if not auth_file:raise ProtocolError("Auth Denied")
            client_pub = Encryption.decryptGCM(self._handshakes[cid].get(timeout=5), tss)
            ekey = Encryption.kdf_fast(Encryption.shared_secret(open(auth_file[:-4] + ".prv", "rb").read(), client_pub), tss)
            def send_enc(data):
                nonlocal sc
                ctr = sc.to_bytes(8, "big")
                sc += 1
                self._send_q.put((cid, HANDSHAKE_EID, ctr + Encryption.encryptGCM(data, ekey, aad=HANDSHAKE_EID + ctr + b"1")))
            def recv_enc():
                nonlocal rc
                payload = self._handshakes[cid].get(timeout=5)
                ctr = payload[:8]
                rc += 1
                return Encryption.decryptGCM(payload[8:], ekey, aad=HANDSHAKE_EID + ctr + b"0")
            sc, rc = 0, 0
            tp = Encryption.gen_ed25519(True)
            send_enc(tp[1])
            pub = recv_enc()
            nonce = os.urandom(256)
            send_enc(nonce)
            cnonce = recv_enc()
            send_enc(Encryption.ed25519_sign(tp[0], cnonce))
            if Encryption.ed25519_verify(pub, recv_enc()) != nonce:raise ProtocolError("Bad Sig")
            with self._lock:
                self._keys[cid] = ekey
                self._counters[cid] = [sc, rc]
                self._handshakes.pop(cid, None)
        except Exception:
            self._kill_client(cid)
    def _kill_client(self, cid):
        with self._lock:
            self._keys.pop(cid, None)
            self._counters.pop(cid, None)
            self._handshakes.pop(cid, None)
            self._q_bytes.pop(cid, None)
    def _loop(self):
        poller = zmq.Poller()
        poller.register(self.sock, zmq.POLLIN)
        while self._running:
            try:
                while not self._send_q.empty():
                    item = self._send_q.get_nowait()
                    if item is None:break
                    cid, eid, frames = item
                    self.sock.send_multipart([cid, eid, frames])
                events = dict(poller.poll(10))
                if self.sock in events and events[self.sock] == zmq.POLLIN:
                    cid, eid, payload = self.sock.recv_multipart()[:3]
                    with self._lock:
                        curr = self._q_bytes.get(cid, 0) + len(payload)
                        if curr > MAX_QUEUE_BYTES:
                            self._kill_client(cid)
                            continue
                        self._q_bytes[cid] = curr
                    if cid not in self._keys:
                        with self._lock:
                            if cid not in self._handshakes:
                                self._handshakes[cid] = queue.Queue()
                                threading.Thread(target=self._hs_worker, args=(cid, payload), daemon=True).start()
                            else:self._handshakes[cid].put(payload)
                        continue
                    with self._lock:
                        ekey = self._keys[cid]
                        self._counters[cid][1] += 1
                        self._eid_map[eid] = cid
                        self._q_bytes[cid] -= len(payload)
                    ctr = payload[:8]
                    data = Encryption.decryptGCM(payload[8:], ekey, aad=eid + ctr + b"0")
                    if self.on_exchange and eid != HANDSHAKE_EID:
                        should_run = False
                        with self._lock:
                            if eid not in self._seen_eids:
                                self._seen_eids[eid] = True
                                if len(self._seen_eids) > 10000:
                                    for k in list(self._seen_eids.keys())[:-5000]:del self._seen_eids[k]
                                should_run = True
                        if should_run:
                            try:self.on_exchange(self, eid, data, cid)
                            except Exception:pass
            except zmq.ZMQError:break
            except Exception:break
        try:
            poller.unregister(self.sock)
            self.sock.close(linger=0)
            self.context.term()
        except Exception:pass
    def send(self, payload, eid=None, client_id=None):
        if eid is None:eid = os.urandom(64)
        with self._lock:
            cid = client_id or self._eid_map.get(eid)
            ekey, sc = self._keys[cid], self._counters[cid][0]
            self._counters[cid][0] += 1
        ctr = sc.to_bytes(8, "big")
        self._send_q.put((cid, eid, ctr + Encryption.encryptGCM(payload, ekey, aad=eid + ctr + b"1")))
    def close(self):
        if not self._running:return
        self._running = False
        self._send_q.put(None)
        if threading.current_thread() != self._io_thread:self._io_thread.join(timeout=2.0)
class TCPClient:
    def __init__(self, host, port, auth_key="./auth_key"):
        self.context = zmq.Context()
        self.sock = self.context.socket(zmq.DEALER)
        self.sock.connect(f"tcp://{host}:{port}")
        self._pending, self._hs_q = {}, queue.Queue()
        self._send_q = queue.Queue()
        self._lock, self._running = threading.Lock(), True
        self.sc, self.rc, self.ekey = 0, 0, None
        self._q_bytes = 0
        pub_key = open(auth_key, "rb").read()
        self._io_thread = threading.Thread(target=self._loop, daemon=True)
        self._io_thread.start()
        tk = Encryption.gen_x25519(True)
        self._send_q.put([HANDSHAKE_EID, tk[1]])
        tss = Encryption.shared_secret(tk[0], self._hs_q.get(timeout=5))
        self._send_q.put([HANDSHAKE_EID, Encryption.encryptGCM(Encryption.basic_kdf(pub_key, b'', 6), tss)])
        keys = Encryption.gen_x25519(True)
        self._send_q.put([HANDSHAKE_EID, Encryption.encryptGCM(keys[1], tss)])
        self.ekey = Encryption.kdf_fast(Encryption.shared_secret(keys[0], pub_key), tss)
        tp = Encryption.gen_ed25519(True)
        self._send_enc(HANDSHAKE_EID, tp[1])
        pub = self._recv_enc(HANDSHAKE_EID, self._hs_q.get(timeout=5))
        nonce = os.urandom(256)
        self._send_enc(HANDSHAKE_EID, nonce)
        snonce = self._recv_enc(HANDSHAKE_EID, self._hs_q.get(timeout=5))
        self._send_enc(HANDSHAKE_EID, Encryption.ed25519_sign(tp[0], snonce))
        if Encryption.ed25519_verify(pub, self._recv_enc(HANDSHAKE_EID, self._hs_q.get(timeout=5))) != nonce:raise ProtocolError("Bad Sig")
    def _send_enc(self, eid, payload):
        ctr = self.sc.to_bytes(8, "big")
        self.sc += 1
        self._send_q.put([eid, ctr + Encryption.encryptGCM(payload, self.ekey, aad=eid + ctr + b"0")])
    def _recv_enc(self, eid, raw_payload):
        ctr = raw_payload[:8]
        self.rc += 1
        return Encryption.decryptGCM(raw_payload[8:], self.ekey, aad=eid + ctr + b"1")
    def send(self, payload, eid=None) -> bytes:
        if eid is None:eid = os.urandom(64)
        with self._lock:self._pending[eid] = queue.Queue()
        self._send_enc(eid, payload)
        return eid
    def recv(self, eid:bytes, timeout:float = None) -> bytes:
        with self._lock:q = self._pending.get(eid)
        if not q:return None
        try:
            raw = q.get(timeout=timeout)
            with self._lock:self._q_bytes -= len(raw)
            return self._recv_enc(eid, raw)
        finally:
            with self._lock:self._pending.pop(eid, None)
    def _loop(self):
        poller = zmq.Poller()
        poller.register(self.sock, zmq.POLLIN)
        while self._running:
            try:
                while not self._send_q.empty():
                    frames = self._send_q.get_nowait()
                    if frames is None:break
                    self.sock.send_multipart(frames)
                events = dict(poller.poll(10))
                if self.sock in events and events[self.sock] == zmq.POLLIN:
                    eid, payload = self.sock.recv_multipart()[:2]
                    payload_len = len(payload)
                    with self._lock:
                        self._q_bytes += payload_len
                        if self._q_bytes > MAX_QUEUE_BYTES:
                            self._running = False
                            break
                    if self.ekey is None:self._hs_q.put(payload)
                    else:
                        with self._lock:q = self._pending.get(eid) if eid != HANDSHAKE_EID else self._hs_q
                        if q:q.put(payload)
                        else:
                            with self._lock:self._q_bytes -= payload_len
            except zmq.ZMQError:break
            except Exception:break
        try:
            poller.unregister(self.sock)
            self.sock.close(linger=0)
            self.context.term()
        except Exception:pass
    def close(self):
        if not self._running:return
        self._running = False
        self._send_q.put(None)
        if threading.current_thread() != self._io_thread:self._io_thread.join(timeout=2.0)
