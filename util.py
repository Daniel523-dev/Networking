import os
def create(path: str) -> None:
    os.makedirs(os.sep.join(path.split(os.sep)[:-1]), exist_ok=True)
    try:os.remove(path)
    except:pass
    try:
        with open(path, 'x') as f:f.write('')
    except:pass
def int_input(prompt: str, min: int=None, max: int=None) -> int:
    while True:
        try:
            num=input(prompt)
            if num=='':return
            num=int(num)
            if min!=None:
                if num<min:continue
            if max!=None:
                if num>max:continue
            return num
        except:pass
def test_main(name='') -> bool:
    import tempfile
    import psutil
    for x in os.listdir(tempfile.gettempdir()):
        if not os.path.exists(tempfile.gettempdir() + os.sep+x):continue
        if 'thread_lock' in x:
            if not psutil.pid_exists(int(x[x.index('thread_lock')+11:])):
                try:os.remove(tempfile.gettempdir() + os.sep+x)
                except:pass
        if name+' '+str(os.getppid()) in x:
            return False
        if name+' '+str(os.getpid()) in x:
            return True
    tempfile.NamedTemporaryFile(dir=tempfile.gettempdir(), prefix='.', suffix=f'{name} thread_lock'+str(os.getpid()), delete=False)
    return True
def get_pid() -> int:return os.getpid() if test_main() else os.getppid()
def compress(data: bytes, fast: bool=False, level: bool=9, FORCE_TYPE: int=None) -> bytes:
    import zlib, gzip, bz2, lzma, brotli, lz4.frame, zstandard
    level_equivalents=[level,round(level*11/9),level,level,None,round(level*16/9),round(level*22/9)]
    _compress=[lambda d:zlib.compress(d, level_equivalents[0]),
               lambda d:brotli.compress(d, quality=level_equivalents[1]),
               lambda d:gzip.compress(d, level_equivalents[2]),
               lambda d:bz2.compress(d, level_equivalents[3]),
               lambda d:lzma.compress(d),
               lambda d:lz4.frame.compress(d, level_equivalents[5]),
               lambda d:zstandard.ZstdCompressor(level=level_equivalents[6]).compress(d)]
    repeat=True
    while repeat:
        repeat=False
        tmp=[]
        if not FORCE_TYPE:tmp.append(data)
        for x in range(len(_compress)):
            if fast and x==2:break
            if FORCE_TYPE and FORCE_TYPE!=x:continue
            tmp.append(_compress[x](data))
        Len=list(map(len, tmp))
        Min=min(Len)
        repeat=Min<Len[0] and not fast
        data=tmp[Len.index(Min)]
        if fast:return data
    return data
def decompress(data: bytes, fast: bool=False, FORCE_TYPE: int=None) -> bytes:
    import zlib, gzip, bz2, lzma, brotli, lz4.frame, zstandard
    _decompress=[lambda d:zlib.decompress(d),
                 lambda d:brotli.decompress(d),
                 lambda d:gzip.decompress(d),
                 lambda d:bz2.decompress(d),
                 lambda d:lzma.decompress(d),
                 lambda d:lz4.frame.decompress(d),
                 lambda d:zstandard.ZstdDecompressor().decompress(d)]
    repeat=True
    while repeat:
        repeat=False
        for x in range(len(_decompress)):
            if fast and x==2:return data
            if FORCE_TYPE and FORCE_TYPE!=x:continue
            try:data=_decompress[x](data)
            except:pass
    return data
BUFFER_SIZE=1048576
def to_hex(data):
    import binascii, pickle
    if isinstance(data, str):data = str_to_bytes(data)
    if not isinstance(data, (bytes, bytearray)):data = pickle.dumps(data)
    chunk_size = BUFFER_SIZE
    return ''.join([binascii.hexlify(data[i:i + chunk_size]).decode('utf-8') for i in range(0, len(data), chunk_size)])
def from_hex(data):
    import binascii
    if isinstance(data, (bytes, bytearray)):data=bytes_to_str(data)
    try:
        return b''.join([binascii.unhexlify(data[i:i + BUFFER_SIZE * 2]) for i in range(0, len(data), BUFFER_SIZE * 2)])
    except:return b''
def str_to_bytes(data):
    import numpy as np
    if isinstance(data,bytes):return data
    return bytes(np.frombuffer(data.encode('latin1'), dtype=np.uint8))
def bytes_to_str(data):
    try:data=data.tobytes()
    except:pass
    try:data=data.decode('latin1')
    except:pass
    return data
def get_folder_size(folder_path):return sum(sum(os.path.getsize(path+os.sep+f) for f in files if os.path.exists(path+os.sep+f)) for path,_,files in os.walk(folder_path) if os.path.exists(path))
