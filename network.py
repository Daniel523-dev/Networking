import os, queue, socket, struct, threading, time, select, traceback, hashlib, hmac, Encryption
RECV_CHUNK= 1024 * 1024
START = b"\\S"
END = b"\\E"
EID_SIZE = 64
LEN_SIZE = 4
HEADER_SIZE = 2 + EID_SIZE + LEN_SIZE
QUEUE_TTL = 60
GCM_OVERHEAD = 60
MAX_QUEUE_SIZE = 128 * 1024 * 1024
def create_auth_keys(d, n):
    os.makedirs(d, exist_ok=True)
    [os.remove(os.path.join(d, f)) for f in os.listdir(d) if os.path.isfile(os.path.join(d, f)) and not f.endswith(('.prv', '.pub'))]
    stems = {os.path.splitext(f)[0] for f in os.listdir(d) if f.endswith(('.prv', '.pub'))}
    pairs = []
    for s in stems:
        prv, pub = os.path.join(d, s+'.prv'), os.path.join(d, s+'.pub')
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
            if os.path.exists(p): os.path.exists(p) and os.remove(p)  
    while len(pairs) < n:
        try:
            prv_b, pub_b = Encryption.gen_x25519(True)
            fid = Encryption.gen_id()
            fid = fid.hex() if isinstance(fid, bytes) else str(fid)
            prv, pub = os.path.join(d, fid+'.prv'), os.path.join(d, fid+'.pub')
            with open(prv, 'wb') as f:f.write(prv_b)
            with open(pub, 'wb') as f:f.write(pub_b)
            pairs.append((prv, pub))
        except Exception:break
    return pairs
def is_path_valid(path_str):
    try:
        if not isinstance(path_str, (str, bytes)) or not path_str:return False
        os.path.split(os.path.abspath(path_str))
        return True
    except (TypeError, ValueError, OSError):return False
class ProtocolError(Exception):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,*kwargs)
        print('protocol error')
        print(args,kwargs)
def recv_exact(sock, size):
    data = bytearray()
    start=time.perf_counter()
    while len(data) < size:
        if time.perf_counter()-start>5:raise TimeoutError
        chunk = sock.recv(min(size - len(data),RECV_CHUNK))
        if not chunk:raise ConnectionError("Connection closed")
        data.extend(chunk)
    return bytes(data)
def escape(data):return data.replace(b"\\", b"\\\\")
def unescape(data):
    if b"\\" not in data:return data
    out = bytearray()
    mv = memoryview(data)
    n = len(mv)
    i = 0
    while i < n:
        idx = data.find(b"\\", i)
        if idx == -1:out.extend(mv[i:]);break
        out.extend(mv[i:idx])
        if idx + 1 >= n or mv[idx + 1] != 92:raise ProtocolError("Invalid escape")
        out.append(92)
        i = idx + 2
    return bytes(out)
def build(payload, eid):
    if not isinstance(payload, bytes):raise TypeError("payload must be bytes")
    if len(eid) != EID_SIZE:raise ValueError("eid must be 64 bytes")
    return START + eid + struct.pack("!I", len(payload)) + escape(payload) + END, eid
def find_end(buf):
    i = 0
    while i < len(buf) - 1:
        if buf[i:i + 2] == END:
            n = 1;j = i - 1
            while j >= 0 and buf[j] == 92:n += 1;j -= 1
            if n & 1:return i
        i += 1
    return -1
def parse(frame):
    if not frame.startswith(START) or len(frame) < HEADER_SIZE:raise ProtocolError("Invalid frame")
    p = 2
    eid = frame[p:p + EID_SIZE]
    p += EID_SIZE
    length = struct.unpack("!I", frame[p:p + LEN_SIZE])[0]
    p += LEN_SIZE
    payload = unescape(frame[p:])
    if len(payload) != length:raise ProtocolError("Length mismatch")
    return eid, payload
class EIDQueues:
    def __init__(self):
        self.queues = {}
        self.sizes = {}
        self.eid_cid = {}
        self.timestamps = {}
        self.condition = threading.Condition()
    @property
    def exchanges(self):
        with self.condition:return list(self.queues.keys())
    def _cleanup(self):
        now = time.monotonic()
        for eid, last_update in list(self.timestamps.items()):
            if now - last_update >= QUEUE_TTL:
                cid = self.eid_cid.get(eid)
                self.queues.pop(eid, None)
                self.timestamps.pop(eid, None)
                self.eid_cid.pop(eid, None)
                if cid and cid not in self.eid_cid.values():self.sizes.pop(cid, None)
    def add(self, eid, cid, payload=None):
        with self.condition:
            self._cleanup()
            if eid not in self.queues:
                self.queues[eid] = queue.Queue()
                self.eid_cid[eid] = cid
            if cid not in self.sizes:self.sizes[cid] = 0
            self.timestamps[eid] = time.monotonic()
            if payload is not None:
                s = len(payload)
                if self.sizes[cid] + s > MAX_QUEUE_SIZE:raise MemoryError('Recv queue full')
                self.queues[eid].put((payload, s))
                self.sizes[cid] += s
                self.condition.notify_all()
    def recv(self, eid, timeout=None):
        with self.condition:
            deadline = None if timeout is None else time.monotonic() + timeout
            while True:
                self._cleanup()
                if eid in self.queues:
                    q = self.queues[eid]
                    try:
                        payload, s = q.get_nowait()
                        cid = self.eid_cid.get(eid)
                        if cid in self.sizes:
                            self.sizes[cid] -= s
                            if self.sizes[cid] < 0:self.sizes[cid] = 0
                        return payload
                    except queue.Empty:pass
                if deadline is None:wait = QUEUE_TTL
                else:
                    wait = deadline - time.monotonic()
                    if wait <= 0:raise TimeoutError("Timed out waiting for EID")
                self.condition.wait(min(wait, QUEUE_TTL))
class TCPConnection:
    def __init__(self, sock, encryption_key, client_id=None, server=True):
        self.type_flag=b'1' if server else b'0'
        self.remote_type_flag=b'0' if server else b'1'
        self.sock, self.shared_secret, self.buffer = sock, encryption_key, bytearray()
        self.send_lock, self.close_lock, self.closed = threading.Lock(), threading.Lock(), False
        self.ID = client_id
        self.newest_rx_time = 0.0
    def send(self, payload, eid=None):
        if self.closed: raise ConnectionError("Connection closed")
        eid = os.urandom(EID_SIZE) if eid == None else eid
        encrypted = Encryption.encryptGCM(struct.pack("!d", time.monotonic()) + payload, self.shared_secret,aad=eid+self.type_flag)
        message, eid = build(encrypted, eid)
        with self.send_lock:
            if self.closed: raise ConnectionError("Connection closed")
            self.sock.sendall(message)
        return eid
    def _more(self):
        try: data = self.sock.recv(RECV_CHUNK)
        except OSError as e:
            if self.closed: raise ConnectionError("Connection closed") from e
            raise
        if not data: raise ConnectionError("Peer closed connection")
        self.buffer.extend(data)
    def _start(self):
        while True:
            p = self.buffer.find(START)
            if p >= 0:
                if p: del self.buffer[:p]
                return
            if len(self.buffer) > 1: del self.buffer[:-1]
            self._more()
    def recv(self):
        while True:
            self._start()
            while len(self.buffer) < HEADER_SIZE: self._more()
            length = struct.unpack("!I", self.buffer[2 + EID_SIZE : 2 + EID_SIZE + LEN_SIZE])[0]
            expected = HEADER_SIZE + length
            while True:
                end = find_end(self.buffer)
                if end >= 0:
                    frame = bytes(self.buffer[:end])
                    del self.buffer[: end + 2]
                    try:
                        eid, encrypted = parse(frame)
                        decrypted = Encryption.decryptGCM(encrypted, self.shared_secret,aad=eid+self.remote_type_flag)
                        if len(decrypted) < 8:raise ValueError("Payload missing timestamp")
                        msg_time = struct.unpack("!d", decrypted[:8])[0]
                        if msg_time <= self.newest_rx_time:break
                        self.newest_rx_time = msg_time
                        return eid, decrypted[8:]
                    except ProtocolError: break
                    except Exception as e:
                        traceback.print_exception(e)
                        self.close()
                        raise ConnectionError("Invalid encrypted message") from e
                if len(self.buffer) >= expected:
                    del self.buffer[:2]
                    break
                self._more()
    def close(self):
        with self.close_lock:
            if self.closed: return
            self.closed = True
            try: self.sock.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            try: self.sock.close()
            except OSError: pass
class TCPServer:
    def __init__(self,host,port,backlog=100,on_exchange = None,auth_key_dir = None, auth_keys = 64):
        if not is_path_valid(auth_key_dir):raise ValueError('An auth key directory is required')
        create_auth_keys(auth_key_dir,auth_keys)
        self.auth_key_dir=auth_key_dir
        self.host,self.port,self.backlog=host,port,backlog
        self.on_exchange=on_exchange
        self.sock=None
        self.running=False
        self.connections=set()
        self.connections_lock=threading.Lock()
        self.queues=EIDQueues()
        self.sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.sock.bind((host,port))
        self.sock.listen(backlog)
        self.sock.setblocking(False)
        self.running=True
        threading.Thread(target=self._accept_loop,daemon=True).start()
        threading.Thread(target=self._receive_loop,daemon=True).start()
    def setup_connection(self,sock):
        try:
            temp_keys=Encryption.gen_x25519(True)
            sock.sendall(temp_keys[1])
            temp_ss=Encryption.shared_secret(temp_keys[0],recv_exact(sock,len(temp_keys[1])))
            _hash=Encryption.decryptGCM(recv_exact(sock,GCM_OVERHEAD+6),temp_ss)
            file=''
            for x in os.listdir(self.auth_key_dir):
                try:
                    if not x.endswith('.pub'):continue
                    with open(os.path.join(self.auth_key_dir,x),'rb') as f:
                        if hmac.compare_digest(_hash,hashlib.sha3_256(f.read()).digest()[:6]):file=os.path.join(self.auth_key_dir,x)
                except OSError:continue
            if file=='':raise ProtocolError('Client Authentication Denied')
            with open(file[:-4]+'.prv','rb') as f:
                out=Encryption.kdf_fast(Encryption.shared_secret(f.read(),Encryption.decryptGCM(recv_exact(sock,len(temp_keys[1])+GCM_OVERHEAD),temp_ss)),temp_ss),_hash
                ekey=out[0]
            test_pair=Encryption.gen_ed25519(True)
            sock.sendall(Encryption.encryptGCM(test_pair[1],ekey))
            pub=Encryption.decryptGCM(recv_exact(sock,len(test_pair[1]) + GCM_OVERHEAD),ekey)
            nonce=os.urandom(256)
            sock.sendall(Encryption.encryptGCM(nonce,ekey))
            sock.sendall(Encryption.encryptGCM(Encryption.ed25519_sign(test_pair[0],Encryption.decryptGCM(recv_exact(sock,256 + GCM_OVERHEAD),ekey)),ekey))
            if Encryption.ed25519_verify(pub,Encryption.decryptGCM(recv_exact(sock,370 + GCM_OVERHEAD),ekey)) != nonce:raise ProtocolError('AUTHENTICATION CHECK INVALID!') # the verify function will thow an error on invalid signatue, if ProtocolError is thrown here, something is funky
            return out
        except Exception as e:
            traceback.print_exception(e)
            raise
    def _accept_loop(self):
        while self.running:
            try:
                sock,_=self.sock.accept()
                sock.setblocking(True)
                encryption_key,client_id=self.setup_connection(sock)
                connection=TCPConnection(sock,encryption_key,client_id,True)
            except OSError:
                if not self.running:break
                continue
            except Exception as e:
                traceback.print_exception(e)
                try:sock.close()
                except OSError:pass
                continue
            with self.connections_lock:self.connections.add(connection)
    def _receive_loop(self):
        while self.running:
            with self.connections_lock:cs=list(self.connections)
            if not cs:
                time.sleep(.01)
                continue
            try:readable,_,_=select.select([c.sock for c in cs],[],[],.1)
            except (OSError,ValueError):continue
            for sock in readable:
                c=next((x for x in cs if x.sock is sock),None)
                if c == None:continue
                try:eid,payload=c.recv()
                except (ConnectionError,OSError):
                    c.close()
                    with self.connections_lock:self.connections.discard(c)
                    continue
                if (self.on_exchange != None) and (eid not in self.queues.exchanges):threading.Thread(target=self._run_exchange,args=(eid,payload,c.ID),daemon=True).start()
                else:
                    try:self.queues.add(eid,c.ID,payload)
                    except MemoryError:
                        c.close()
                        with self.connections_lock:self.connections.discard(c)
                        continue
    def _run_exchange(self,eid,payload,client_id):
        try:self.on_exchange(self,eid,payload,client_id)
        except Exception as e:traceback.print_exception(e)
    def recv(self,eid,timeout=None):return self.queues.recv(eid,timeout)
    def send(self,payload,eid=None):
        with self.connections_lock:c=next(iter(self.connections),None)
        if c == None:raise ConnectionError("No connections")
        return c.send(payload,eid)
    def close(self):
        if not self.running:return
        self.running=False
        if self.sock:
            try:self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            try:self.sock.close()
            except OSError:pass
            self.sock=None
        with self.connections_lock:
            cs=list(self.connections)
            self.connections.clear()
        for c in cs:c.close()
class TCPClient:
    def __init__(self, host, port, auth_key='', on_callback=None):
        if auth_key == '':raise ValueError('An auth key is required')
        self.auth_key = auth_key
        self.host, self.port = host, port
        self.on_callback = on_callback
        self.running = False
        self.receiver_thread = None
        self.queues = EIDQueues()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        try:self.connection = TCPConnection(sock, self.setup_connection(sock), Encryption.gen_id(), False)
        except Exception as e:
            traceback.print_exception(e)
            sock.close()
            raise e
        self.running = True
        self.receiver_thread = threading.Thread(target=self._receive_loop, daemon=True)
        self.receiver_thread.start()
    def _receive_loop(self):
        try:
            while self.running:
                try:eid, payload = self.connection.recv()
                except (ConnectionError, OSError):break
                if (self.on_callback is not None) and (eid not in self.queues.exchanges):threading.Thread(target=self._run_callback, args=(eid, payload), daemon=True).start()
                else:self.queues.add(eid, b'', payload)
        finally:self.running = False
    def _run_callback(self, eid, payload):
        try:self.on_callback(self, eid, payload)
        except Exception as e:traceback.print_exception(e)
    def setup_connection(self,sock):
        temp_keys=Encryption.gen_x25519(True)
        sock.sendall(temp_keys[1])
        pub=recv_exact(sock,len(temp_keys[1]))
        temp_ss=Encryption.shared_secret(temp_keys[0],pub)
        with open(self.auth_key,'rb') as f:key=f.read()
        sock.sendall(Encryption.encryptGCM(hashlib.sha3_256(key).digest()[:6],temp_ss))
        keys=Encryption.gen_x25519(True)
        sock.sendall(Encryption.encryptGCM(keys[1],temp_ss))
        ekey=Encryption.kdf_fast(Encryption.shared_secret(keys[0],key),temp_ss)
        test_pair=Encryption.gen_ed25519(True)
        sock.sendall(Encryption.encryptGCM(test_pair[1],ekey))
        pub=Encryption.decryptGCM(recv_exact(sock,len(test_pair[1]) + GCM_OVERHEAD),ekey)
        nonce=os.urandom(256)
        sock.sendall(Encryption.encryptGCM(nonce,ekey))
        sock.sendall(Encryption.encryptGCM(Encryption.ed25519_sign(test_pair[0],Encryption.decryptGCM(recv_exact(sock, 256 + GCM_OVERHEAD),ekey)),ekey))
        if Encryption.ed25519_verify(pub,Encryption.decryptGCM(recv_exact(sock,370 + GCM_OVERHEAD),ekey)) != nonce:raise ProtocolError('AUTHENTICATION CHECK INVALID!')
        return ekey
    def send(self,payload,eid=None):
        if self.connection == None:raise RuntimeError("Not connected")
        return self.connection.send(payload,eid)
    def recv(self,eid,timeout=None):return self.queues.recv(eid,timeout)
    def close(self):
        self.running=False
        c=self.connection
        self.connection=None
        if c:c.close()
        t=self.receiver_thread
        self.receiver_thread=None
        if t and t.is_alive() and t != threading.current_thread():t.join(timeout=1)
