import hpack

def recvall(s,l):
  b = bytearray(b'')
  while len(b) < l:
    b2 = s.recv(l-len(b))
    if len(b2) == 0:
      return bytes(b)
    b += b2
  return bytes(b)

def recv_frame(s):
  ls = recvall(s, 3)
  if len(ls) < 3:
    return ls
  l = (ord(ls[0])<<16) | (ord(ls[1])<<8) | (ord(ls[2])<<0)
  ss = recvall(s, l+9-3)
  return ls+ss

class frame(object):
  def __init__(this):
    this.type = None
    this.flags = None
    this.stream_id = None
    this.payload = None
  
class frame_settings(frame):
  def __init__(this):
    this.type = 0x4
    this.flags = None
    this.stream_id = 0x0
    this.settings = list()

class frame_window_update(frame):
  def __init__(this):
    this.type = 0x8
    this.flags = None
    this.stream_id = None
    this.increment = None

class frame_headers(frame):
  def __init__(this):
    this.type = 0x1
    this.flags = None
    this.stream_id = 0x0
    this.headers = b''

class frame_push_promise(frame):
  def __init__(this):
    this.type = 0x5
    this.flags = None
    this.stream_id = 0x0
    this.promised_stream_id = 0x0
    this.headers = b''

class frame_data(frame):
  def __init__(this):
    this.type = 0x0
    this.flags = None
    this.stream_id = 0x0
    this.data = b''

class frame_rst_stream(frame):
  def __init__(this):
    this.type = 0x0
    this.flags = None
    this.stream_id = 0x0
    this.error_code = 0x0


def encode_frame(f):
  l = len(f.payload)
  s = bytearray(b'')
  if ((l>>16) & 0xFF) != (l>>16):
    assert False
  s.append((l>>16)&0xFF)
  s.append((l>>8)&0xFF)
  s.append((l>>0)&0xFF)
  s.append(f.type)
  s.append(f.flags)
  if ((f.stream_id>>24)&0x7f) != (f.stream_id>>24):
    assert False
  s.append((f.stream_id>>24)&0x7f)
  s.append((f.stream_id>>16)&0xff)
  s.append((f.stream_id>>8)&0xff)
  s.append((f.stream_id>>0)&0xff)
  s += f.payload
  return bytes(s)

def decode_frame(s):
  f = frame()
  l = (ord(s[0])<<16) | (ord(s[1])<<8) | (ord(s[2])<<0)
  if len(s) != l + 9:
    assert False
  f.type = ord(s[3])
  f.flags = ord(s[4])
  f.stream_id = (ord(s[5])<<24) | (ord(s[6])<<16) | (ord(s[7])<<8) | (ord(s[8])<<0)
  f.stream_id &= 0x7FFFFFFF
  f.payload = s[9:]
  return f

class setting(object):
  def __init__(this, ident, val):
    this.ident = ident
    this.val = val

class setting_header_table_size(setting):
  def __init__(this, val):
    super(setting_header_table_size, this).__init__(0x1, val)

class setting_enable_push(setting):
  def __init__(this, val):
    super(setting_enable_push, this).__init__(0x2, val)

class setting_max_concurrent_streams(setting):
  def __init__(this, val):
    super(setting_max_concurrent_streams, this).__init__(0x3, val)

class setting_initial_window_size(setting):
  def __init__(this, val):
    super(setting_initial_window_size, this).__init__(0x4, val)

class setting_max_frame_size(setting):
  def __init__(this, val):
    super(setting_max_frame_size, this).__init__(0x5, val)

class setting_max_header_list_size(setting):
  def __init__(this, val):
    super(setting_max_header_list_size, this).__init__(0x6, val)

def decode_settings(bs):
  fraw = decode_frame(bs)
  f = frame_settings()
  f.flags = fraw.flags
  pay = fraw.payload
  if len(pay) % 6 != 0:
    assert False
  for n in range(0, len(pay)/6):
    start = 6*n
    end = 6*n+6
    setting = pay[start:end]
    ident = (ord(setting[0])<<8) | ord(setting[1])
    val = (ord(setting[2])<<24) | (ord(setting[3])<<16) | (ord(setting[4])<<8) | (ord(setting[5])<<0)
    if ident == 1:
      f.settings.append(setting_header_table_size(val))
    elif ident == 2:
      f.settings.append(setting_enable_push(val))
    elif ident == 3:
      f.settings.append(setting_max_concurrent_streams(val))
    elif ident == 4:
      f.settings.append(setting_initial_window_size(val))
    elif ident == 5:
      f.settings.append(setting_max_frame_size(val))
    elif ident == 6:
      f.settings.append(setting_max_header_list_size(val))
    else:
      f.settings.append(setting(ident, val))
  return f

def decode_rst_stream(bs):
  fraw = decode_frame(bs)
  f = frame_rst_stream()
  f.flags = fraw.flags
  f.stream_id = fraw.stream_id
  pay = fraw.payload
  assert len(pay) == 4
  f.error_code = (ord(pay[0])<<24) | (ord(pay[1])<<16) | (ord(pay[2])<<8) | (ord(pay[3]))
  return f

def decode_window_update(bs):
  fraw = decode_frame(bs)
  f = frame_window_update()
  f.flags = fraw.flags
  f.stream_id = fraw.stream_id
  pay = fraw.payload
  assert len(pay) == 4
  f.increment = ((ord(pay[0])&0x7f)<<24) | (ord(pay[1])<<16) | (ord(pay[2])<<8) | (ord(pay[3]))
  return f

def decode_data(bs):
  fraw = decode_frame(bs)
  f = frame_data()
  f.flags = fraw.flags
  f.stream_id = fraw.stream_id
  pay = fraw.payload
  padlen = 0
  if f.flags & 0x8:
    padlen = pay[0]
    pay = pay[1:]
  if padlen:
    pay = pay[:-padlen]
  f.data = pay
  return f

def decode_push_promise(bs):
  fraw = decode_frame(bs)
  f = frame_push_promise()
  f.flags = fraw.flags
  f.stream_id = fraw.stream_id
  pay = fraw.payload
  padlen = 0
  if f.flags & 0x8:
    padlen = pay[0]
    pay = pay[1:]
  f.promised_stream_id = ((ord(pay[0])&0x7f)<<24) | (ord(pay[1])<<16) | (ord(pay[2])<<8) | (ord(pay[3])<<0)
  pay = pay[4:]
  if padlen:
    pay = pay[:-padlen]
  f.headers = pay
  return f

def decode_headers(bs):
  fraw = decode_frame(bs)
  f = frame_headers()
  f.flags = fraw.flags
  f.stream_id = fraw.stream_id
  pay = fraw.payload
  #minlen = 5
  #if f.flags & 0x8:
  #  minlen = 6
  #if len(pay) < minlen:
  #  assert False
  padlen = 0
  if f.flags & 0x8:
    padlen = ord(pay[0])
    pay = pay[1:]
  if f.flags & 0x20:
    exclusive = ord(pay[0])>>7
    streamdep = ((ord(pay[0])&0x7f)<<24) | ((ord(pay[1]))<<16) | (ord(pay[2])<<8) | (ord(pay[3])<<0)
    weight = ord(pay[4])
    pay = pay[5:]
  if padlen:
    pay = pay[:-padlen]
  f.headers = pay
  return f
  
      

def decode_any(s):
  f = decode_frame(s)
  if f.type == 0:
    return decode_data(s)
  if f.type == 1:
    return decode_headers(s)
  if f.type == 3:
    return decode_rst_stream(s)
  if f.type == 4:
    return decode_settings(s)
  if f.type == 5:
    return decode_push_promise(s)
  if f.type == 8:
    return decode_window_update(s)
  

def encode_data(stream_id, data, end_stream, maxsz):
  fs = []
  pad_length = 0
  first = True
  while len(data) > 0:
    f = frame()
    if first:
      f.type = 0x0
    else:
      f.type = 0x0
    f.flags = 0
    #end_data = (len(data) <= maxsz - 4)
    end_data = (len(data) <= maxsz)
    if end_data:
      cur_data = data
      data = b''
    else:
      #cur_data = data[:maxsz-4]
      #data = data[maxsz-4:]
      cur_data = data[:maxsz]
      data = data[maxsz:]
    if end_stream and data == b'':
      f.flags |= 0x1
    if pad_length and first:
      f.flags |= 0x8
    f.stream_id = stream_id
    s = bytearray(b'')
    if first and pad_length:
      s += pad_length
    s += cur_data
    if first:
      s += pad_length * b"\0"
    f.payload = bytes(s)
    fs.append(f)
    if first:
      first = False
  return fs

def encode_headers(stream_id, exclusive, dependency, weight, headers, end_stream, priority, maxsz):
  fs = []
  pad_length = 0
  first = True
  while len(headers) > 0:
    f = frame()
    if first:
      f.type = 0x1
    else:
      f.type = 0x9
    f.flags = 0
    end_headers = (len(headers) <= maxsz - 4)
    if end_headers:
      cur_headers = headers
      headers = b''
    else:
      cur_headers = headers[:maxsz-4]
      headers = headers[maxsz-4:]
    if end_stream and first:
      f.flags |= 0x1
    if end_headers:
      f.flags |= 0x4
    if pad_length and first:
      f.flags |= 0x8
    if priority and first:
      f.flags |= 0x20
    f.stream_id = stream_id
    s = bytearray(b'')
    if first and pad_length:
      s += pad_length
    if ((dependency>>24)&0x7f) != (dependency>>24):
      assert False
    if first and priority:
      exclusive = exclusive and 1 or 0
      s.append(((dependency>>24)&0x7f) | (exclusive<<7))
      s.append((dependency>>16)&0xff)
      s.append((dependency>>8)&0xff)
      s.append((dependency>>0)&0xff)
      s.append((dweight>>0)&0xff)
    s += cur_headers
    if first:
      s += pad_length * b"\0"
    f.payload = bytes(s)
    fs.append(f)
    if first:
      first = False
  return fs

def encode_prority(stream_id, exclusive, dependency, weight):
  f = frame()
  f.type = 0x2
  f.flags = 0x0
  f.stream_id = stream_id
  ba = bytearray(b'')
  exclusive = exlusive and 1 or 0
  ba.append(((error_code>>24)&0x7f) | (exclusive<<7))
  ba.append((error_code>>16)&0xff)
  ba.append((error_code>>8)&0xff)
  ba.append((error_code>>0)&0xff)
  ba.append((weight>>0)&0xff)
  f.payload = bytes(ba)
  return f

def encode_rst_stream(stream_id, error_code):
  f = frame()
  f.type = 0x3
  f.flags = 0x0
  f.stream_id = stream_id
  ba = bytearray(b'')
  ba.append((error_code>>24))
  ba.append((error_code>>16)&0xff)
  ba.append((error_code>>8)&0xff)
  ba.append((error_code>>0)&0xff)
  f.payload = bytes(ba)
  return f

def encode_settings(settings, ack):
  f = frame()
  f.type = 0x4
  f.flags = (ack and 0x1) or 0x0
  f.stream_id = 0
  ba = bytearray(b'')
  for setting in settings:
    k = setting.ident
    v = setting.val
    ba.append(k>>8)
    ba.append(k&0xff)
    ba.append((v>>24))
    ba.append((v>>16)&0xff)
    ba.append((v>>8)&0xff)
    ba.append((v>>0)&0xff)
  f.payload = bytes(ba)
  return f

def encode_push_promise(stream_id, promised_sid, headers, maxsz):
  fs = []
  pad_length = 0
  first = True
  while len(headers) > 0:
    f = frame()
    if first:
      f.type = 0x5
    else:
      f.type = 0x9
    f.flags = 0
    end_headers = (len(headers) <= maxsz - 4)
    if end_headers:
      cur_headers = headers
      headers = b''
    else:
      cur_headers = headers[:maxsz-4]
      headers = headers[maxsz-4:]
    if end_headers:
      f.flags |= 0x4
    if pad_length and first:
      f.flags |= 0x8
    f.stream_id = stream_id
    s = bytearray(b'')
    if first and pad_length:
      s += pad_length
    if ((promised_sid>>24)&0x7f) != (promised_sid>>24):
      assert False
    if first:
      s.append((promised_sid>>24)&0x7f)
      s.append((promised_sid>>16)&0xff)
      s.append((promised_sid>>8)&0xff)
      s.append((promised_sid>>0)&0xff)
    s += cur_headers
    if first:
      s += pad_length * b"\0"
    f.payload = bytes(s)
    fs.append(f)
    if first:
      first = False
  return fs

def encode_ping(opaque_data, resp):
  if len(opaque_data) != 8:
    assert False
  f = frame()
  f.stream_id = 0
  f.type = 0x6
  f.flags = ((resp) and 0x1) or 0x0
  f.payload = bytes(opaque_data)
  return f

def encode_goaway(last_stream_id, error_code):
  f = frame()
  f.stream_id = 0
  f.type = 0x7
  f.flags = 0x0
  s = bytearray(b'')
  if ((last_stream_id>>24) & 0x7f) != (last_stream_id>>24):
    assert False
  s.append((last_stream_id>>24)&0x7f)
  s.append((last_stream_id>>16)&0xff)
  s.append((last_stream_id>>8)&0xff)
  s.append((last_stream_id>>0)&0xff)
  s.append((error_code>>24)&0x7f)
  s.append((error_code>>16)&0xff)
  s.append((error_code>>8)&0xff)
  s.append((error_code>>0)&0xff)
  f.payload = bytes(s)
  return f

def encode_window_update(stream_id, increment):
  f = frame()
  f.stream_id = stream_id
  f.type = 0x8
  f.flags = 0x0
  s = bytearray(b'')
  if ((increment>>24) & 0x7f) != (increment>>24):
    assert False
  s.append((increment>>24)&0x7f)
  s.append((increment>>16)&0xff)
  s.append((increment>>8)&0xff)
  s.append((increment>>0)&0xff)
  f.payload = bytes(s)
  return f


if __name__ == '__main__':
  settings = encode_settings([
      setting_header_table_size(4096),
      setting_enable_push(0),
      #setting_max_concurrent_streams(100),
      setting_initial_window_size(65535),
      setting_max_frame_size(16384),
      #setting_max_header_list_size(16384),
    ], 0)
  settingsframe = encode_frame(settings)
  settings2 = decode_any(settingsframe)
  assert type(settings2.settings[0]) == setting_header_table_size
  assert settings2.settings[0].val == 4096
  assert type(settings2.settings[1]) == setting_enable_push
  assert settings2.settings[1].val == 0
  assert type(settings2.settings[2]) == setting_initial_window_size
  assert settings2.settings[2].val == 65535
  assert type(settings2.settings[3]) == setting_max_frame_size
  assert settings2.settings[3].val == 16384
  
  hdrs = hpack.encodehdrs([('Foo', '1'), ('Bar', '2'), ('Baz', '3')])
  print(repr(hdrs))
  pushpromises = encode_push_promise(1, 2, hdrs, 16384)
  print(repr(pushpromises[0].payload))
  ping = encode_ping(8*b"\0", 0)
  print(repr(ping.payload))
