import os, queue, time, hmac, zmq, threading, zipfile, Encryption, util
from zxcvbn import zxcvbn
from concurrent.futures import ThreadPoolExecutor
HANDSHAKE_EID = b"__HANDSHAKE__"
MAX_QUEUE_BYTES = 256 * 1024 * 1024
class ProtocolError(Exception):pass
SALT_SIZE = 64
def _derive_at_rest_key(password, salt_or_path):
    if not password:raise ValueError("Password cannot be empty.")
    result = zxcvbn(password)
    guesses_log10 = result.get("guesses_log10", 0)
    if guesses_log10 <= 8:raise ValueError(f"Password too weak (log10 guesses:{guesses_log10:.2f}). Must be > 8.")
    if isinstance(salt_or_path, bytes):
        salt = salt_or_path
        if len(salt) != SALT_SIZE:raise ValueError(f"Salt must be exactly {SALT_SIZE} bytes.")
    else:
        salt_file = os.fspath(salt_or_path)
        if os.path.exists(salt_file):
            with open(salt_file, "rb") as f:salt = f.read()
            if len(salt) != SALT_SIZE:raise ValueError(f"Salt file must contain exactly {SALT_SIZE} bytes.")
        else:
            salt = os.urandom(SALT_SIZE)
            with open(salt_file, "wb") as f:f.write(salt)
    return Encryption.kdf_slow(password.encode("utf-8"), salt)
def validate_auth_keys(d, at_rest_key):
    os.makedirs(d, exist_ok=True)
    [os.remove(os.path.join(d, f)) for f in os.listdir(d) if os.path.isfile(os.path.join(d, f)) and not f.endswith(('.prv', '.pub'))]
    stems = {os.path.splitext(f)[0] for f in os.listdir(d) if f.endswith(('.prv', '.pub'))}
    pairs = []
    for s in stems:
        prv, pub = os.path.join(d, s + '.prv'), os.path.join(d, s + '.pub')
        if os.path.isfile(prv) and os.path.isfile(pub):
            try:
                with open(prv, 'rb') as f:p_bytes = Encryption.decryptGCM(f.read(), at_rest_key)
                with open(pub, 'rb') as f:b_bytes = Encryption.decryptGCM(f.read(), at_rest_key)
                tk = Encryption.gen_x25519(True)
                if Encryption.shared_secret(tk[0], b_bytes) == Encryption.shared_secret(p_bytes, tk[1]):
                    pairs.append((prv, pub))
                    continue
            except Exception:pass
        for p in (prv, pub):
            if os.path.exists(p):os.remove(p)
    return pairs
class TCPServer:
    def __init__(self, host, port, password, auth_key_password, auth_key_dir="./keys", salt_file="./server_salt.bin", on_exchange=None):
        self.auth_key_dir = auth_key_dir
        self.pool=ThreadPoolExecutor(4)
        self.on_exchange = on_exchange
        self.auth_key_password=auth_key_password
        self.at_rest_key = _derive_at_rest_key(password, salt_file)
        validate_auth_keys(self.auth_key_dir, self.at_rest_key)
        self.admin_ed = Encryption.gen_ed25519(True)
        admin_zip_path = os.path.join(self.auth_key_dir, "auth_key")
        salt=os.urandom(64)
        key=Encryption.kdf_slow(util.str_to_bytes(self.auth_key_password),salt)
        with zipfile.ZipFile(admin_zip_path, 'w') as zf:
            zf.writestr('admin.prv', Encryption.encryptGCM(self.admin_ed[0],key))
            zf.writestr('admin.pub', Encryption.encryptGCM(self.admin_ed[1],key))
            zf.writestr('salt.bin', salt)
        self.context = zmq.Context()
        self.sock = self.context.socket(zmq.ROUTER)
        self.sock.bind(f"tcp://{host}:{port}")
        self._eid_map, self._keys, self._handshakes, self._counters, self._recv_counters = {}, {}, {}, {}, {}
        self._q_bytes = {}
        self._seen_eids = {}
        self._eid_activity = {}
        self._last_cleanup = time.time()
        self._send_q = queue.Queue(10)
        self._lock, self._running = threading.Lock(), True
        self._io_thread = threading.Thread(target=self._loop, daemon=True)
        self._io_thread.start()
    def _hs_worker(self, cid, client_temp_pub):
        try:
            if client_temp_pub.startswith(b"REQ_KEY"):
                try:
                    admin_zip_path = os.path.join(self.auth_key_dir, "auth_key")
                    req_tk_pub = client_temp_pub[7:]
                    stk = Encryption.gen_x25519(True)
                    tss_req = Encryption.shared_secret(stk[0], req_tk_pub)
                    nonce = os.urandom(32)
                    self._send_q.put((cid, HANDSHAKE_EID, stk[1] + nonce))
                    sig_payload = self._handshakes[cid].get(timeout=5)
                    signature = Encryption.decryptGCM(sig_payload, tss_req)
                    if Encryption.ed25519_verify(self.admin_ed[1], signature) != nonce:raise ProtocolError("Bad Admin Sig")
                    prv_b, pub_b = Encryption.gen_x25519(True)
                    fid = os.urandom(64).hex()
                    prv, pub = os.path.join(self.auth_key_dir, fid + '.prv'), os.path.join(self.auth_key_dir, fid + '.pub')
                    with open(prv, 'wb') as f:f.write(Encryption.encryptGCM(prv_b, self.at_rest_key))
                    with open(pub, 'wb') as f:f.write(Encryption.encryptGCM(pub_b, self.at_rest_key))
                    auth_pub_sig = Encryption.ed25519_sign(self.admin_ed[0], pub_b)
                    auth_pub_len = len(pub_b).to_bytes(4, 'big')
                    payload = auth_pub_len + pub_b + auth_pub_sig
                    self._send_q.put((cid, HANDSHAKE_EID, Encryption.encryptGCM(payload, tss_req)))
                    client_temp_pub = self._handshakes[cid].get(timeout=10)
                finally:
                    salt=os.urandom(64)
                    key=Encryption.kdf_slow(util.str_to_bytes(self.auth_key_password),salt)
                    try:os.remove(admin_zip_path)
                    except:pass
                    with zipfile.ZipFile(admin_zip_path, 'w') as zf:
                        zf.writestr('admin.prv', Encryption.encryptGCM(self.admin_ed[0],key))
                        zf.writestr('admin.pub', Encryption.encryptGCM(self.admin_ed[1],key))
                        zf.writestr('salt.bin', salt)
            tk = Encryption.gen_x25519(True)
            self._send_q.put((cid, HANDSHAKE_EID, tk[1]))
            tss = Encryption.shared_secret(tk[0], client_temp_pub)
            _hash = Encryption.decryptGCM(self._handshakes[cid].get(timeout=5), tss)
            auth_file = ""
            if os.path.exists(self.auth_key_dir):
                for x in os.listdir(self.auth_key_dir):
                    if x.endswith(".pub"):
                        raw_pub = Encryption.decryptGCM(open(os.path.join(self.auth_key_dir, x), "rb").read(), self.at_rest_key)
                        if hmac.compare_digest(_hash, Encryption.basic_kdf(raw_pub, b'', 6)):
                            auth_file = os.path.join(self.auth_key_dir, x)
            if not auth_file:raise ProtocolError("Auth Denied")
            client_pub = Encryption.decryptGCM(self._handshakes[cid].get(timeout=5), tss)
            raw_prv = Encryption.decryptGCM(open(auth_file[:-4] + ".prv", "rb").read(), self.at_rest_key)
            ekey = Encryption.kdf_fast(Encryption.shared_secret(raw_prv, client_pub), tss)
            def send_enc(data):
                nonlocal sc
                ctr = sc.to_bytes(8, "big")
                sc += 1
                self._send_q.put((cid, HANDSHAKE_EID, ctr + Encryption.encryptGCM(data, ekey, aad=HANDSHAKE_EID + ctr + b"1")))
            def recv_enc():
                nonlocal rc
                payload = self._handshakes[cid].get(timeout=5)
                ctr = payload[:8]
                _ctr = int.from_bytes(ctr,'big')
                if _ctr<=rc:raise ProtocolError
                rc = _ctr
                return Encryption.decryptGCM(payload[8:], ekey, aad=HANDSHAKE_EID + ctr + b"0")
            sc, rc = 1, 0
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
        except Exception as e:self._kill_client(cid)
    def _kill_client(self, cid):
        with self._lock:
            self._keys.pop(cid, None)
            self._counters.pop(cid, None)
            self._recv_counters.pop(cid, None)
            self._handshakes.pop(cid, None)
            self._q_bytes.pop(cid, None)
            dead_eids = [eid for eid, owner in self._eid_map.items() if owner == cid]
            for eid in dead_eids:
                self._eid_map.pop(eid, None)
                self._eid_activity.pop(eid, None)
            self._seen_eids.pop(eid, None)
    def _loop(self):
        poller = zmq.Poller()
        poller.register(self.sock, zmq.POLLIN)
        while self._running:
            try:
                now = time.time()
                if now - self._last_cleanup > 10.0:
                    self._last_cleanup = now
                    with self._lock:
                        expired = [e for e, t in self._eid_activity.items() if now - t > 60.0]
                        for e in expired:
                            self._eid_activity.pop(e, None)
                            self._eid_map.pop(e, None)
                            self._seen_eids.pop(e, None)
                while not self._send_q.empty():
                    item = self._send_q.get_nowait()
                    if item is None:break
                    cid, eid, frames = item
                    self.sock.send_multipart([cid, eid, frames])
                events = dict(poller.poll(10))
                if self.sock in events and events[self.sock] == zmq.POLLIN:
                    cid, *_frames=self.sock.recv_multipart()[:3]
                    if len(_frames)!=3:self._kill_client(cid);continue
                    cid, eid, payload = _frames
                    with self._lock:
                        curr = self._q_bytes.get(cid, 0) + len(payload)
                        if curr > MAX_QUEUE_BYTES:
                            self._kill_client(cid)
                            continue
                        self._q_bytes[cid] = curr
                    if cid not in self._keys:
                        with self._lock:
                            if cid not in self._handshakes:
                                self._handshakes[cid] = queue.Queue(10)
                                self.pool.submit(self._hs_worker, cid, payload)
                            else:self._handshakes[cid].put(payload)
                        continue
                    with self._lock:
                        ekey = self._keys[cid]
                        if self._eid_map[eid].get(eid,cid)!=cid:continue
                        self._eid_map[eid] = cid
                        self._q_bytes[cid] -= len(payload)
                        if eid != HANDSHAKE_EID:self._eid_activity[eid] = time.time()
                    ctr = payload[:8]
                    _ctr=int.from_bytes(ctr,'big')
                    if _ctr<=self._counters[cid][1]:self._kill_client(cid);continue
                    self._counters[cid][1]=_ctr
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
            except Exception as e:self._kill_client(cid)
        try:
            poller.unregister(self.sock)
            self.sock.close(linger=0)
            self.context.term()
        except Exception:pass
    def send(self, payload, eid=None, client_id=None):
        if eid is None:eid = os.urandom(64)
        with self._lock:
            cid = client_id or self._eid_map.get(eid)
            if eid != HANDSHAKE_EID:self._eid_activity[eid] = time.time()
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
    def __init__(self,host,port,password,auth_key="./auth_key",auth_key_password_callback=None):
        self.context = zmq.Context()
        self.sock = zmq.Context().socket(zmq.DEALER)
        self.sock.connect(f"tcp://{host}:{port}")
        self._pending, self._hs_q = {}, queue.Queue(10)
        self._send_q = queue.Queue(10)
        self._eid_activity = {}
        self._last_cleanup = time.time()
        self._lock, self._running = threading.Lock(), True
        self.sc, self.rc, self.ekey = 1, 0, None
        self._q_bytes = 0
        self._io_thread = threading.Thread(target=self._loop, daemon=True)
        self._io_thread.start()
        is_zip = False
        try:is_zip = zipfile.is_zipfile(auth_key)
        except Exception:pass
        if is_zip:
            with zipfile.ZipFile(auth_key, "r") as zf:
                for filename in ["admin.prv", "admin.pub", "salt.bin"]:
                    file_info = zf.getinfo(filename)
                    if file_info.file_size > 1024 * 1024:raise ProtocolError(f"File {filename} exceeds safety limits.")
                admin_prv = zf.read("admin.prv")
                admin_pub = zf.read("admin.pub")
                salt = zf.read("salt.bin")
            key = Encryption.kdf_slow(util.str_to_bytes(auth_key_password_callback()), salt)
            admin_prv = Encryption.decryptGCM(admin_prv, key)
            admin_pub = Encryption.decryptGCM(admin_pub, key)
            req_tk = Encryption.gen_x25519(True)
            self._send_q.put([HANDSHAKE_EID, b"REQ_KEY" + req_tk[1]])
            resp = self._hs_q.get(timeout=5)
            stk_len = len(req_tk[1])
            server_stk_pub = resp[:stk_len]
            nonce = resp[stk_len:]
            tss_req = Encryption.shared_secret(req_tk[0], server_stk_pub)
            sig = Encryption.ed25519_sign(admin_prv, nonce)
            self._send_q.put([HANDSHAKE_EID,Encryption.encryptGCM(sig, tss_req)])
            enc_auth = self._hs_q.get(timeout=5)
            auth_data = Encryption.decryptGCM(enc_auth, tss_req)
            auth_pub_len = int.from_bytes(auth_data[:4], "big")
            auth_pub = auth_data[4:4 + auth_pub_len]
            auth_pub_sig = auth_data[4 + auth_pub_len:]
            if Encryption.ed25519_verify(admin_pub, auth_pub_sig) != auth_pub:raise ProtocolError("Bad Server Auth Sig")
            salt = os.urandom(SALT_SIZE)
            self.at_rest_key = _derive_at_rest_key(password, salt)
            with open(auth_key, "wb") as f:
                f.write(salt)
                f.write(Encryption.encryptGCM(auth_pub, self.at_rest_key))
            pub_key = auth_pub
        else:
            with open(auth_key, "rb") as f:
                salt = f.read(SALT_SIZE)
                encrypted_pub = f.read()
            if len(salt) != SALT_SIZE:raise ProtocolError("Invalid auth_key: missing salt")
            if not encrypted_pub:raise ProtocolError("Invalid auth_key: missing key data")
            self.at_rest_key = _derive_at_rest_key(password, salt)
            pub_key = Encryption.decryptGCM(encrypted_pub, self.at_rest_key)
        tk = Encryption.gen_x25519(True)
        self._send_q.put([HANDSHAKE_EID, tk[1]])
        tss = Encryption.shared_secret(tk[0],self._hs_q.get(timeout=10))
        self._send_q.put([HANDSHAKE_EID,Encryption.encryptGCM(Encryption.basic_kdf(pub_key, b"", 6),tss)])
        keys = Encryption.gen_x25519(True)
        self._send_q.put([HANDSHAKE_EID,Encryption.encryptGCM(keys[1], tss)])
        self.ekey = Encryption.kdf_fast(Encryption.shared_secret(keys[0], pub_key),tss)
        tp = Encryption.gen_ed25519(True)
        self._send_enc(HANDSHAKE_EID, tp[1])
        pub = self._recv_enc(HANDSHAKE_EID,self._hs_q.get(timeout=5))
        nonce = os.urandom(256)
        self._send_enc(HANDSHAKE_EID, nonce)
        snonce = self._recv_enc(HANDSHAKE_EID,self._hs_q.get(timeout=5))
        self._send_enc(HANDSHAKE_EID,Encryption.ed25519_sign(tp[0], snonce))
        if Encryption.ed25519_verify(pub,self._recv_enc(HANDSHAKE_EID,self._hs_q.get(timeout=5))) != nonce:raise ProtocolError("Bad Sig")
    def _send_enc(self, eid, payload):
        ctr = self.sc.to_bytes(8, "big")
        self.sc += 1
        self._send_q.put([eid, ctr + Encryption.encryptGCM(payload, self.ekey, aad=eid + ctr + b"0")])
    def _recv_enc(self, eid, raw_payload):
        ctr = raw_payload[:8]
        _ctr=int.from_bytes(ctr,'big')
        if _ctr<=self.rc:self.close();raise ProtocolError('Counter Error')
        self.rc = _ctr
        return Encryption.decryptGCM(raw_payload[8:], self.ekey, aad=eid + ctr + b"1")
    def send(self, payload, eid=None) -> bytes:
        if eid is None:eid = os.urandom(64)
        with self._lock:
            self._pending[eid] = queue.Queue(10)
            if eid != HANDSHAKE_EID:self._eid_activity[eid] = time.time()
        self._send_enc(eid, payload)
        return eid
    def recv(self, eid:bytes, timeout:float = None) -> bytes:
        with self._lock:
            q = self._pending.get(eid)
            if eid != HANDSHAKE_EID:self._eid_activity[eid] = time.time()
        if not q:return None
        try:
            raw = q.get(timeout=timeout)
            with self._lock:self._q_bytes -= len(raw)
            return self._recv_enc(eid, raw)
        finally:
            with self._lock:
                self._pending.pop(eid, None)
                self._eid_activity.pop(eid, None)
    def _loop(self):
        poller = zmq.Poller()
        poller.register(self.sock, zmq.POLLIN)
        while self._running:
            try:
                now = time.time()
                if now - self._last_cleanup > 10.0:
                    self._last_cleanup = now
                    with self._lock:
                        expired = [e for e, t in self._eid_activity.items() if now - t > 60.0]
                        for e in expired:
                            self._eid_activity.pop(e, None)
                            q = self._pending.pop(e, None)
                            if q:
                                while not q.empty():
                                    try:self._q_bytes -= len(q.get_nowait())
                                    except queue.Empty:break
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
                        if eid != HANDSHAKE_EID:self._eid_activity[eid] = time.time()
                        if self._q_bytes > MAX_QUEUE_BYTES:
                            self._running = False
                            break
                    if self.ekey is None:self._hs_q.put(payload)
                    else:
                        with self._lock:q = self._pending.get(eid) if eid != HANDSHAKE_EID else self._hs_q
                        if q:q.put(payload)
                        else:
                            with self._lock:self._q_bytes -= payload_len
            except Exception as e:
                print(f"[!] Network loop died: {type(e).__name__}: {e}")
                break
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
