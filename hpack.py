import collections

class hdrtbl(object):
  stattbl = [
    (":authority",""),
    (":method","GET"),
    (":method","POST"),
    (":path","/"),
    (":path","/index.html"),
    (":scheme","http"),
    (":scheme","https"),
    (":status","200"),
    (":status","204"),
    (":status","206"),
    (":status","304"),
    (":status","400"),
    (":status","404"),
    (":status","500"),
    ("accept-charset",""),
    ("accept-encoding","gzip, deflate"),
    ("accept-language",""),
    ("accept-ranges",""),
    ("accept",""),
    ("access-control-allow-origin",""),
    ("age",""),
    ("allow",""),
    ("authorization",""),
    ("cache-control",""),
    ("content-disposition",""),
    ("content-encoding",""),
    ("content-language",""),
    ("content-length",""),
    ("content-location",""),
    ("content-range",""),
    ("content-type",""),
    ("cookie",""),
    ("date",""),
    ("etag",""),
    ("expect",""),
    ("expires",""),
    ("from",""),
    ("host",""),
    ("if-match",""),
    ("if-modified-since",""),
    ("if-none-match",""),
    ("if-range",""),
    ("if-unmodified-since",""),
    ("last-modified",""),
    ("link",""),
    ("location",""),
    ("max-forwards",""),
    ("proxy-authenticate",""),
    ("proxy-authorization",""),
    ("range",""),
    ("referer",""),
    ("refresh",""),
    ("retry-after",""),
    ("server",""),
    ("set-cookie",""),
    ("strict-transport-security",""),
    ("transfer-encoding",""),
    ("user-agent",""),
    ("vary",""),
    ("via",""),
    ("www-authenticate",""),
  ]
  def __init__(this):
    this.dyntbl = collections.deque()
  def dynsz(this):
    sz = 0
    for k,v in this.dyntbl:
      sz += 32 + len(k) + len(v)
    return sz
  def evict(this, maxsz):
    if maxsz < 0:
      maxsz = 0
    while this.dynsz() > maxsz and len(this.dyntbl) > 0:
      del this.dyntbl[-1]
  def add(this, maxsz, k, v):
    newentrysz = 32 + len(k) + len(v)
    this.evict(maxsz - newentrysz)
    if newentrysz <= maxsz:
      this.dyntbl.appendleft((k,v))
  def tblget(this, i):
    assert i > 0
    i -= 1
    if i < len(this.stattbl):
      return this.stattbl[i]
    i -= len(this.stattbl)
    assert i < len(this.dyntbl)
    return this.dyntbl[i]


class bitstr(object):
  def __init__(this, maxsz, hdrtbl):
    this.ar = bytearray(b"")
    this.readidx = 0
    this.N = 8
    this.maxsz = maxsz
    this.hdrtbl = hdrtbl

def intencode(bs,i):
  if bs.N == 8:
    bs.ar.append(b"\0")
  if i < ((1<<bs.N) - 1):
    bs.ar[-1] |= i
    bs.N = 8
  else:
    bs.ar[-1] |= ((1<<bs.N)-1)
    i -= ((1<<bs.N) - 1)
    while i >= 128:
      bs.ar.append((i%128) + 128)
      i = i / 128
    bs.ar.append(i)
    bs.N = 8

def intdecode(bs):
  i = bs.ar[bs.readidx] & ((1<<bs.N) - 1)
  bs.readidx += 1
  if i < ((1<<bs.N) - 1):
    return i
  else:
    M = 0
    while True:
      B = bs.ar[bs.readidx]
      bs.readidx += 1
      i = i + ((B & 127) << M)
      M = M + 7
      if (B & 128) != 128:
        break
    return i

huffmantbl = [
(0b1111111111000                      ,13),
(0b11111111111111111011000            ,23),
(0b1111111111111111111111100010       ,28),
(0b1111111111111111111111100011       ,28),
(0b1111111111111111111111100100       ,28),
(0b1111111111111111111111100101       ,28),
(0b1111111111111111111111100110       ,28),
(0b1111111111111111111111100111       ,28),
(0b1111111111111111111111101000       ,28),
(0b111111111111111111101010           ,24),
(0b111111111111111111111111111100     ,30),
(0b1111111111111111111111101001       ,28),
(0b1111111111111111111111101010       ,28),
(0b111111111111111111111111111101     ,30),
(0b1111111111111111111111101011       ,28),
(0b1111111111111111111111101100       ,28),
(0b1111111111111111111111101101       ,28),
(0b1111111111111111111111101110       ,28),
(0b1111111111111111111111101111       ,28),
(0b1111111111111111111111110000       ,28),
(0b1111111111111111111111110001       ,28),
(0b1111111111111111111111110010       ,28),
(0b111111111111111111111111111110     ,30),
(0b1111111111111111111111110011       ,28),
(0b1111111111111111111111110100       ,28),
(0b1111111111111111111111110101       ,28),
(0b1111111111111111111111110110       ,28),
(0b1111111111111111111111110111       ,28),
(0b1111111111111111111111111000       ,28),
(0b1111111111111111111111111001       ,28),
(0b1111111111111111111111111010       ,28),
(0b1111111111111111111111111011       ,28),
(0b010100                              ,6),
(0b1111111000                         ,10),
(0b1111111001                         ,10),
(0b111111111010                       ,12),
(0b1111111111001                      ,13),
(0b010101                              ,6),
(0b11111000                            ,8),
(0b11111111010                        ,11),
(0b1111111010                         ,10),
(0b1111111011                         ,10),
(0b11111001                            ,8),
(0b11111111011                        ,11),
(0b11111010                            ,8),
(0b010110                              ,6),
(0b010111                              ,6),
(0b011000                              ,6),
(0b00000                               ,5),
(0b00001                               ,5),
(0b00010                               ,5),
(0b011001                              ,6),
(0b011010                              ,6),
(0b011011                              ,6),
(0b011100                              ,6),
(0b011101                              ,6),
(0b011110                              ,6),
(0b011111                              ,6),
(0b1011100                             ,7),
(0b11111011                            ,8),
(0b111111111111100                    ,15),
(0b100000                              ,6),
(0b111111111011                       ,12),
(0b1111111100                         ,10),
(0b1111111111010                      ,13),
(0b100001                              ,6),
(0b1011101                             ,7),
(0b1011110                             ,7),
(0b1011111                             ,7),
(0b1100000                             ,7),
(0b1100001                             ,7),
(0b1100010                             ,7),
(0b1100011                             ,7),
(0b1100100                             ,7),
(0b1100101                             ,7),
(0b1100110                             ,7),
(0b1100111                             ,7),
(0b1101000                             ,7),
(0b1101001                             ,7),
(0b1101010                             ,7),
(0b1101011                             ,7),
(0b1101100                             ,7),
(0b1101101                             ,7),
(0b1101110                             ,7),
(0b1101111                             ,7),
(0b1110000                             ,7),
(0b1110001                             ,7),
(0b1110010                             ,7),
(0b11111100                            ,8),
(0b1110011                             ,7),
(0b11111101                            ,8),
(0b1111111111011                      ,13),
(0b1111111111111110000                ,19),
(0b1111111111100                      ,13),
(0b11111111111100                     ,14),
(0b100010                              ,6),
(0b111111111111101                    ,15),
(0b00011                               ,5),
(0b100011                              ,6),
(0b00100                               ,5),
(0b100100                              ,6),
(0b00101                               ,5),
(0b100101                              ,6),
(0b100110                              ,6),
(0b100111                              ,6),
(0b00110                               ,5),
(0b1110100                             ,7),
(0b1110101                             ,7),
(0b101000                              ,6),
(0b101001                              ,6),
(0b101010                              ,6),
(0b00111                               ,5),
(0b101011                              ,6),
(0b1110110                             ,7),
(0b101100                              ,6),
(0b01000                               ,5),
(0b01001                               ,5),
(0b101101                              ,6),
(0b1110111                             ,7),
(0b1111000                             ,7),
(0b1111001                             ,7),
(0b1111010                             ,7),
(0b1111011                             ,7),
(0b111111111111110                    ,15),
(0b11111111100                        ,11),
(0b11111111111101                     ,14),
(0b1111111111101                      ,13),
(0b1111111111111111111111111100       ,28),
(0b11111111111111100110               ,20),
(0b1111111111111111010010             ,22),
(0b11111111111111100111               ,20),
(0b11111111111111101000               ,20),
(0b1111111111111111010011             ,22),
(0b1111111111111111010100             ,22),
(0b1111111111111111010101             ,22),
(0b11111111111111111011001            ,23),
(0b1111111111111111010110             ,22),
(0b11111111111111111011010            ,23),
(0b11111111111111111011011            ,23),
(0b11111111111111111011100            ,23),
(0b11111111111111111011101            ,23),
(0b11111111111111111011110            ,23),
(0b111111111111111111101011           ,24),
(0b11111111111111111011111            ,23),
(0b111111111111111111101100           ,24),
(0b111111111111111111101101           ,24),
(0b1111111111111111010111             ,22),
(0b11111111111111111100000            ,23),
(0b111111111111111111101110           ,24),
(0b11111111111111111100001            ,23),
(0b11111111111111111100010            ,23),
(0b11111111111111111100011            ,23),
(0b11111111111111111100100            ,23),
(0b111111111111111011100              ,21),
(0b1111111111111111011000             ,22),
(0b11111111111111111100101            ,23),
(0b1111111111111111011001             ,22),
(0b11111111111111111100110            ,23),
(0b11111111111111111100111            ,23),
(0b111111111111111111101111           ,24),
(0b1111111111111111011010             ,22),
(0b111111111111111011101              ,21),
(0b11111111111111101001               ,20),
(0b1111111111111111011011             ,22),
(0b1111111111111111011100             ,22),
(0b11111111111111111101000            ,23),
(0b11111111111111111101001            ,23),
(0b111111111111111011110              ,21),
(0b11111111111111111101010            ,23),
(0b1111111111111111011101             ,22),
(0b1111111111111111011110             ,22),
(0b111111111111111111110000           ,24),
(0b111111111111111011111              ,21),
(0b1111111111111111011111             ,22),
(0b11111111111111111101011            ,23),
(0b11111111111111111101100            ,23),
(0b111111111111111100000              ,21),
(0b111111111111111100001              ,21),
(0b1111111111111111100000             ,22),
(0b111111111111111100010              ,21),
(0b11111111111111111101101            ,23),
(0b1111111111111111100001             ,22),
(0b11111111111111111101110            ,23),
(0b11111111111111111101111            ,23),
(0b11111111111111101010               ,20),
(0b1111111111111111100010             ,22),
(0b1111111111111111100011             ,22),
(0b1111111111111111100100             ,22),
(0b11111111111111111110000            ,23),
(0b1111111111111111100101             ,22),
(0b1111111111111111100110             ,22),
(0b11111111111111111110001            ,23),
(0b11111111111111111111100000         ,26),
(0b11111111111111111111100001         ,26),
(0b11111111111111101011               ,20),
(0b1111111111111110001                ,19),
(0b1111111111111111100111             ,22),
(0b11111111111111111110010            ,23),
(0b1111111111111111101000             ,22),
(0b1111111111111111111101100          ,25),
(0b11111111111111111111100010         ,26),
(0b11111111111111111111100011         ,26),
(0b11111111111111111111100100         ,26),
(0b111111111111111111111011110        ,27),
(0b111111111111111111111011111        ,27),
(0b11111111111111111111100101         ,26),
(0b111111111111111111110001           ,24),
(0b1111111111111111111101101          ,25),
(0b1111111111111110010                ,19),
(0b111111111111111100011              ,21),
(0b11111111111111111111100110         ,26),
(0b111111111111111111111100000        ,27),
(0b111111111111111111111100001        ,27),
(0b11111111111111111111100111         ,26),
(0b111111111111111111111100010        ,27),
(0b111111111111111111110010           ,24),
(0b111111111111111100100              ,21),
(0b111111111111111100101              ,21),
(0b11111111111111111111101000         ,26),
(0b11111111111111111111101001         ,26),
(0b1111111111111111111111111101       ,28),
(0b111111111111111111111100011        ,27),
(0b111111111111111111111100100        ,27),
(0b111111111111111111111100101        ,27),
(0b11111111111111101100               ,20),
(0b111111111111111111110011           ,24),
(0b11111111111111101101               ,20),
(0b111111111111111100110              ,21),
(0b1111111111111111101001             ,22),
(0b111111111111111100111              ,21),
(0b111111111111111101000              ,21),
(0b11111111111111111110011            ,23),
(0b1111111111111111101010             ,22),
(0b1111111111111111101011             ,22),
(0b1111111111111111111101110          ,25),
(0b1111111111111111111101111          ,25),
(0b111111111111111111110100           ,24),
(0b111111111111111111110101           ,24),
(0b11111111111111111111101010         ,26),
(0b11111111111111111110100            ,23),
(0b11111111111111111111101011         ,26),
(0b111111111111111111111100110        ,27),
(0b11111111111111111111101100         ,26),
(0b11111111111111111111101101         ,26),
(0b111111111111111111111100111        ,27),
(0b111111111111111111111101000        ,27),
(0b111111111111111111111101001        ,27),
(0b111111111111111111111101010        ,27),
(0b111111111111111111111101011        ,27),
(0b1111111111111111111111111110       ,28),
(0b111111111111111111111101100        ,27),
(0b111111111111111111111101101        ,27),
(0b111111111111111111111101110        ,27),
(0b111111111111111111111101111        ,27),
(0b111111111111111111111110000        ,27),
(0b11111111111111111111101110         ,26),
(0b111111111111111111111111111111     ,30),
]

class huffmannode(object):
  def __init__(this):
    this.nodes = [None,None]

huffmanroot = huffmannode()
for n in range(257):
  k,l = huffmantbl[n]
  curnode = huffmanroot
  for m in range(l-1, 0, -1):
    b = (k>>m)&1
    if curnode.nodes[b] == None:
      curnode.nodes[b] = huffmannode()
    curnode = curnode.nodes[b]
  b = k&1
  curnode.nodes[b] = n

def bitpos(M):
  return 7-M

def huffmanenc(bs):
  M = 0
  resbs = bytearray(b"")
  for by in bs:
    by = ord(by)
    k,l = huffmantbl[by]
    for n in range(l-1, -1, -1):
      if M == 0:
        resbs.append(0)
      if (k>>n)&1:
        resbs[-1] |= (1<<bitpos(M))
      M += 1
      if M == 8:
        M = 0
  k,l = huffmantbl[256]
  for n in range(l-1, -1, -1):
    if M == 0:
      resbs.append(0)
    if (k>>n)&1:
      resbs[-1] |= (1<<bitpos(M))
    M += 1
    if M == 8:
      M = 0
  return bytes(resbs)
  
def huffmandec(bs):
  M = 0
  idx = 0
  resbs = bytearray(b"")
  while idx < len(bs):
    curnode = huffmanroot
    while idx < len(bs) and type(curnode) != int:
      b = (ord(bs[idx])>>bitpos(M))&1
      M += 1
      if M == 8:
        idx += 1
        M = 0
      curnode = curnode.nodes[b]
    decoded = curnode
    if decoded == 256 or type(decoded) != int:
      break
    resbs.append(decoded)
  return bytes(resbs)

def strdecode(bs):
  H = (bs.ar[bs.readidx]>>7)
  bs.N = 7
  l = intdecode(bs)
  result = bs.ar[bs.readidx : (bs.readidx+l)]
  bs.readidx += l
  if H:
    return huffmandec(bytes(result))
  else:
    return bytes(result)

def strencode(bs, ba):
  bs.ar.append(0)
  bs.N = 7
  intencode(bs, len(ba))
  bs.ar += bytearray(ba)
  bs.N = 8

def hdrencode(bs, k, v):
  bs.ar.append(1<<4)
  strencode(bs, k)
  strencode(bs, v)

def hdrdecode(bs):
  hi = (bs.ar[bs.readidx]>>7)
  bs.N = 7
  if hi == 1:
    i = intdecode(bs)
    return bs.hdrtbl.tblget(i)
  else:
    hilo = (bs.ar[bs.readidx]>>6) & 1
    bs.N = 6
    if hilo == 1:
      i = intdecode(bs)
      if i != 0:
        key = bs.hdrtbl.tblget(i)[0]
        val = strdecode(bs)
        bs.hdrtbl.add(bs.maxsz, key, val)
        return (key, val)
      else:
        key = strdecode(bs)
        val = strdecode(bs)
        bs.hdrtbl.add(bs.maxsz, key, val)
        return (key, val)
    else:
      lohi = (bs.ar[bs.readidx]>>5) & 1
      lolo = (bs.ar[bs.readidx]>>4) & 1
      if (lohi == 0 and lolo == 0) or (lohi == 0 and lolo == 1):
        bs.N = 4
        i = intdecode(bs)
        if i != 0:
          key = bs.hdrtbl.tblget(i)[0]
          val = strdecode(bs)
          return (key, val)
        else:
          key = strdecode(bs)
          val = strdecode(bs)
          return (key, val)
      elif lohi == 1:
        bs.N = 5
        i = intdecode(bs)
        bs.maxsz = i
        bs.hdrtbl.evict(bs.maxsz)
      else:
        assert False
      
bs = bitstr(0, hdrtbl())
bs.ar.append((1<<7) | (1<<6) | (1<<5))
bs.N = 5
intencode(bs, 10)
assert bs.ar == b"\xea"
bs.N = 5
assert intdecode(bs) == 10

bs = bitstr(0, hdrtbl())
bs.ar.append((1<<7) | (1<<6) | (1<<5))
bs.N = 5
intencode(bs, 1337)
assert bs.ar == b"\xff\x9a\x0a"
bs.N = 5
assert intdecode(bs) == 1337

for n in range(0,10000,100):
  s = n*"Foo Bar Baz Quux"
  for m in range(10):
    bs = bitstr(0, hdrtbl())
    for k in range(m):
      strencode(bs, s)
    for k in range(m):
      assert strdecode(bs) == s


assert huffmandec(huffmanenc(b"")) == b""
assert huffmandec(huffmanenc(b"a")) == b"a"
assert huffmandec(huffmanenc(b"Foo")) == b"Foo"
assert huffmandec(b"\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff") == "www.example.com"

bs = bitstr(0, hdrtbl())
hdrencode(bs, "Foo", "Bar")
assert hdrdecode(bs) == ("Foo", "Bar")

def nohuffmantest():
  hdr1 = b"\x82\x86\x84\x41\x0f\x77\x77\x77\x2e\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d"
  bs = bitstr(131072, hdrtbl())
  bs.ar = bytearray(hdr1)
  hdrs = []
  expected = [(':method', 'GET'), (':scheme', 'http'), (':path', '/'), (':authority', 'www.example.com')]
  while bs.readidx < len(bs.ar):
    hdrs.append(hdrdecode(bs))
  assert hdrs == expected
  assert len(bs.hdrtbl.dyntbl) == 1
  assert bs.hdrtbl.dyntbl[0] == (':authority', 'www.example.com')
  assert bs.hdrtbl.dynsz() == 57
  #
  hdr2 = b"\x82\x86\x84\xbe\x58\x08\x6e\x6f\x2d\x63\x61\x63\x68\x65"
  bs = bitstr(131072, bs.hdrtbl)
  bs.ar = bytearray(hdr2)
  hdrs = []
  expected = [(':method', 'GET'), (':scheme', 'http'), (':path', '/'), (':authority', 'www.example.com'), ('cache-control', 'no-cache')]
  while bs.readidx < len(bs.ar):
    hdrs.append(hdrdecode(bs))
  assert hdrs == expected
  assert len(bs.hdrtbl.dyntbl) == 2
  assert bs.hdrtbl.dyntbl[0] == ('cache-control', 'no-cache')
  assert bs.hdrtbl.dyntbl[1] == (':authority', 'www.example.com')
  assert bs.hdrtbl.dynsz() == 110
  #
  hdr3 = b"\x82\x87\x85\xbf\x40\x0a\x63\x75\x73\x74\x6f\x6d\x2d\x6b\x65\x79\x0c\x63\x75\x73\x74\x6f\x6d\x2d\x76\x61\x6c\x75\x65"
  bs = bitstr(131072, bs.hdrtbl)
  bs.ar = bytearray(hdr3)
  hdrs = []
  expected = [(':method', 'GET'), (':scheme', 'https'), (':path', '/index.html'), (':authority', 'www.example.com'), ('custom-key', 'custom-value')]
  while bs.readidx < len(bs.ar):
    hdrs.append(hdrdecode(bs))
  assert hdrs == expected
  assert len(bs.hdrtbl.dyntbl) == 3
  assert bs.hdrtbl.dyntbl[0] == ('custom-key', 'custom-value')
  assert bs.hdrtbl.dyntbl[1] == ('cache-control', 'no-cache')
  assert bs.hdrtbl.dyntbl[2] == (':authority', 'www.example.com')
  assert bs.hdrtbl.dynsz() == 164

def huffmantest():
  hdr1 = b"\x82\x86\x84\x41\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff"
  bs = bitstr(131072, hdrtbl())
  bs.ar = bytearray(hdr1)
  hdrs = []
  expected = [(':method', 'GET'), (':scheme', 'http'), (':path', '/'), (':authority', 'www.example.com')]
  while bs.readidx < len(bs.ar):
    hdrs.append(hdrdecode(bs))
  assert hdrs == expected
  assert len(bs.hdrtbl.dyntbl) == 1
  assert bs.hdrtbl.dyntbl[0] == (':authority', 'www.example.com')
  assert bs.hdrtbl.dynsz() == 57
  #
  hdr2 = b"\x82\x86\x84\xbe\x58\x86\xa8\xeb\x10\x64\x9c\xbf"
  bs = bitstr(131072, bs.hdrtbl)
  bs.ar = bytearray(hdr2)
  hdrs = []
  expected = [(':method', 'GET'), (':scheme', 'http'), (':path', '/'), (':authority', 'www.example.com'), ('cache-control', 'no-cache')]
  while bs.readidx < len(bs.ar):
    hdrs.append(hdrdecode(bs))
  assert hdrs == expected
  assert len(bs.hdrtbl.dyntbl) == 2
  assert bs.hdrtbl.dyntbl[0] == ('cache-control', 'no-cache')
  assert bs.hdrtbl.dyntbl[1] == (':authority', 'www.example.com')
  assert bs.hdrtbl.dynsz() == 110
  #
  hdr3 = b"\x82\x87\x85\xbf\x40\x88\x25\xa8\x49\xe9\x5b\xa9\x7d\x7f\x89\x25\xa8\x49\xe9\x5b\xb8\xe8\xb4\xbf"
  bs = bitstr(131072, bs.hdrtbl)
  bs.ar = bytearray(hdr3)
  hdrs = []
  expected = [(':method', 'GET'), (':scheme', 'https'), (':path', '/index.html'), (':authority', 'www.example.com'), ('custom-key', 'custom-value')]
  while bs.readidx < len(bs.ar):
    hdrs.append(hdrdecode(bs))
  assert hdrs == expected
  assert len(bs.hdrtbl.dyntbl) == 3
  assert bs.hdrtbl.dyntbl[0] == ('custom-key', 'custom-value')
  assert bs.hdrtbl.dyntbl[1] == ('cache-control', 'no-cache')
  assert bs.hdrtbl.dyntbl[2] == (':authority', 'www.example.com')
  assert bs.hdrtbl.dynsz() == 164

def nohuffmanresp():
  hdr1 = b"\x48\x03\x33\x30\x32\x58\x07\x70\x72\x69\x76\x61\x74\x65\x61\x1d\x4d\x6f\x6e\x2c\x20\x32\x31\x20\x4f\x63\x74\x20\x32\x30\x31\x33\x20\x32\x30\x3a\x31\x33\x3a\x32\x31\x20\x47\x4d\x54\x6e\x17\x68\x74\x74\x70\x73\x3a\x2f\x2f\x77\x77\x77\x2e\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d"
  bs = bitstr(256, hdrtbl())
  bs.ar = bytearray(hdr1)
  hdrs = []
  expected = [(':status', '302'), ('cache-control', 'private'), ('date', 'Mon, 21 Oct 2013 20:13:21 GMT'), ('location', 'https://www.example.com')]
  while bs.readidx < len(bs.ar):
    hdrs.append(hdrdecode(bs))
  assert hdrs == expected
  assert len(bs.hdrtbl.dyntbl) == 4
  assert bs.hdrtbl.dyntbl[0] == ('location', 'https://www.example.com')
  assert bs.hdrtbl.dyntbl[1] == ('date', 'Mon, 21 Oct 2013 20:13:21 GMT')
  assert bs.hdrtbl.dyntbl[2] == ('cache-control', 'private')
  assert bs.hdrtbl.dyntbl[3] == (':status', '302')
  assert bs.hdrtbl.dynsz() == 222
  #
  hdr2 = b"\x48\x03\x33\x30\x37\xc1\xc0\xbf"
  bs = bitstr(256, bs.hdrtbl)
  bs.ar = bytearray(hdr2)
  hdrs = []
  expected = [(':status', '307'), ('cache-control', 'private'), ('date', 'Mon, 21 Oct 2013 20:13:21 GMT'), ('location', 'https://www.example.com')]
  while bs.readidx < len(bs.ar):
    hdrs.append(hdrdecode(bs))
  assert hdrs == expected
  assert len(bs.hdrtbl.dyntbl) == 4
  assert bs.hdrtbl.dyntbl[0] == (':status', '307')
  assert bs.hdrtbl.dyntbl[1] == ('location', 'https://www.example.com')
  assert bs.hdrtbl.dyntbl[2] == ('date', 'Mon, 21 Oct 2013 20:13:21 GMT')
  assert bs.hdrtbl.dyntbl[3] == ('cache-control', 'private')
  assert bs.hdrtbl.dynsz() == 222
  #
  hdr3 = b"\x88\xc1\x61\x1d\x4d\x6f\x6e\x2c\x20\x32\x31\x20\x4f\x63\x74\x20\x32\x30\x31\x33\x20\x32\x30\x3a\x31\x33\x3a\x32\x32\x20\x47\x4d\x54\xc0\x5a\x04\x67\x7a\x69\x70\x77\x38\x66\x6f\x6f\x3d\x41\x53\x44\x4a\x4b\x48\x51\x4b\x42\x5a\x58\x4f\x51\x57\x45\x4f\x50\x49\x55\x41\x58\x51\x57\x45\x4f\x49\x55\x3b\x20\x6d\x61\x78\x2d\x61\x67\x65\x3d\x33\x36\x30\x30\x3b\x20\x76\x65\x72\x73\x69\x6f\x6e\x3d\x31"
  bs = bitstr(256, bs.hdrtbl)
  bs.ar = bytearray(hdr3)
  hdrs = []
  expected = [
    (':status', '200'),
    ('cache-control', 'private'),
    ('date', 'Mon, 21 Oct 2013 20:13:22 GMT'),
    ('location', 'https://www.example.com'),
    ('content-encoding', 'gzip'),
    ('set-cookie', 'foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1'),
  ]
  while bs.readidx < len(bs.ar):
    hdrs.append(hdrdecode(bs))
  assert hdrs == expected
  assert len(bs.hdrtbl.dyntbl) == 3
  assert bs.hdrtbl.dyntbl[0] == ('set-cookie', 'foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1')
  assert bs.hdrtbl.dyntbl[1] == ('content-encoding' ,'gzip')
  assert bs.hdrtbl.dyntbl[2] == ('date', 'Mon, 21 Oct 2013 20:13:22 GMT')
  assert bs.hdrtbl.dynsz() == 215


def huffmanresp():
  #hdr1 = b"\x48\x03\x33\x30\x32\x58\x07\x70\x72\x69\x76\x61\x74\x65\x61\x1d\x4d\x6f\x6e\x2c\x20\x32\x31\x20\x4f\x63\x74\x20\x32\x30\x31\x33\x20\x32\x30\x3a\x31\x33\x3a\x32\x31\x20\x47\x4d\x54\x6e\x17\x68\x74\x74\x70\x73\x3a\x2f\x2f\x77\x77\x77\x2e\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d"
  hdr1 = b"\x48\x82\x64\x02\x58\x85\xae\xc3\x77\x1a\x4b\x61\x96\xd0\x7a\xbe\x94\x10\x54\xd4\x44\xa8\x20\x05\x95\x04\x0b\x81\x66\xe0\x82\xa6\x2d\x1b\xff\x6e\x91\x9d\x29\xad\x17\x18\x63\xc7\x8f\x0b\x97\xc8\xe9\xae\x82\xae\x43\xd3"
  bs = bitstr(256, hdrtbl())
  bs.ar = bytearray(hdr1)
  hdrs = []
  expected = [(':status', '302'), ('cache-control', 'private'), ('date', 'Mon, 21 Oct 2013 20:13:21 GMT'), ('location', 'https://www.example.com')]
  while bs.readidx < len(bs.ar):
    hdrs.append(hdrdecode(bs))
  assert hdrs == expected
  assert len(bs.hdrtbl.dyntbl) == 4
  assert bs.hdrtbl.dyntbl[0] == ('location', 'https://www.example.com')
  assert bs.hdrtbl.dyntbl[1] == ('date', 'Mon, 21 Oct 2013 20:13:21 GMT')
  assert bs.hdrtbl.dyntbl[2] == ('cache-control', 'private')
  assert bs.hdrtbl.dyntbl[3] == (':status', '302')
  assert bs.hdrtbl.dynsz() == 222
  #
  #hdr2 = b"\x48\x03\x33\x30\x37\xc1\xc0\xbf"
  hdr2 = b"\x48\x83\x64\x0e\xff\xc1\xc0\xbf"
  bs = bitstr(256, bs.hdrtbl)
  bs.ar = bytearray(hdr2)
  hdrs = []
  expected = [(':status', '307'), ('cache-control', 'private'), ('date', 'Mon, 21 Oct 2013 20:13:21 GMT'), ('location', 'https://www.example.com')]
  while bs.readidx < len(bs.ar):
    hdrs.append(hdrdecode(bs))
  assert hdrs == expected
  assert len(bs.hdrtbl.dyntbl) == 4
  assert bs.hdrtbl.dyntbl[0] == (':status', '307')
  assert bs.hdrtbl.dyntbl[1] == ('location', 'https://www.example.com')
  assert bs.hdrtbl.dyntbl[2] == ('date', 'Mon, 21 Oct 2013 20:13:21 GMT')
  assert bs.hdrtbl.dyntbl[3] == ('cache-control', 'private')
  assert bs.hdrtbl.dynsz() == 222
  #
  #hdr3 = b"\x88\xc1\x61\x1d\x4d\x6f\x6e\x2c\x20\x32\x31\x20\x4f\x63\x74\x20\x32\x30\x31\x33\x20\x32\x30\x3a\x31\x33\x3a\x32\x32\x20\x47\x4d\x54\xc0\x5a\x04\x67\x7a\x69\x70\x77\x38\x66\x6f\x6f\x3d\x41\x53\x44\x4a\x4b\x48\x51\x4b\x42\x5a\x58\x4f\x51\x57\x45\x4f\x50\x49\x55\x41\x58\x51\x57\x45\x4f\x49\x55\x3b\x20\x6d\x61\x78\x2d\x61\x67\x65\x3d\x33\x36\x30\x30\x3b\x20\x76\x65\x72\x73\x69\x6f\x6e\x3d\x31"
  hdr3 = b"\x88\xc1\x61\x96\xd0\x7a\xbe\x94\x10\x54\xd4\x44\xa8\x20\x05\x95\x04\x0b\x81\x66\xe0\x84\xa6\x2d\x1b\xff\xc0\x5a\x83\x9b\xd9\xab\x77\xad\x94\xe7\x82\x1d\xd7\xf2\xe6\xc7\xb3\x35\xdf\xdf\xcd\x5b\x39\x60\xd5\xaf\x27\x08\x7f\x36\x72\xc1\xab\x27\x0f\xb5\x29\x1f\x95\x87\x31\x60\x65\xc0\x03\xed\x4e\xe5\xb1\x06\x3d\x50\x07"
  bs = bitstr(256, bs.hdrtbl)
  bs.ar = bytearray(hdr3)
  hdrs = []
  expected = [
    (':status', '200'),
    ('cache-control', 'private'),
    ('date', 'Mon, 21 Oct 2013 20:13:22 GMT'),
    ('location', 'https://www.example.com'),
    ('content-encoding', 'gzip'),
    ('set-cookie', 'foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1'),
  ]
  while bs.readidx < len(bs.ar):
    hdrs.append(hdrdecode(bs))
  assert hdrs == expected
  assert len(bs.hdrtbl.dyntbl) == 3
  assert bs.hdrtbl.dyntbl[0] == ('set-cookie', 'foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1')
  assert bs.hdrtbl.dyntbl[1] == ('content-encoding' ,'gzip')
  assert bs.hdrtbl.dyntbl[2] == ('date', 'Mon, 21 Oct 2013 20:13:22 GMT')
  assert bs.hdrtbl.dynsz() == 215


nohuffmantest()
huffmantest()

nohuffmanresp()
huffmanresp()
