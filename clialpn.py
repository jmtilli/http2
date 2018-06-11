import socket
import ssl
import hpack
import http2
import time

print ssl.HAS_ALPN

#hostname = "www.hs.fi"
#hostname = "www.google.fi"
#hostname = "nghttp2.org"

#hostname = "localhost"
#port = 8443

hostname = "www.google.fi"
port = 443

context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
context.set_alpn_protocols(['h2'])
context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20")
context.options |= ssl.OP_NO_COMPRESSION
context.options |= (
        ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    )
conn = context.wrap_socket(socket.socket(socket.AF_INET),
                           server_hostname=hostname)
conn.connect((hostname, port))
print(conn.selected_alpn_protocol())

conn.sendall(b'\x50\x52\x49\x20\x2a\x20\x48\x54\x54\x50\x2f\x32\x2e\x30\x0d\x0a\x0d\x0a\x53\x4d\x0d\x0a\x0d\x0a') # MAGIC

settings = http2.encode_frame(http2.encode_settings([
  http2.setting_header_table_size(8192),
  http2.setting_enable_push(1),
  http2.setting_max_concurrent_streams(10),
  http2.setting_initial_window_size(65535),
  #http2.setting_initial_window_size(1),
  http2.setting_max_frame_size(16384),
  http2.setting_max_header_list_size(65536),
], 0))
conn.sendall(settings)
#conn.sendall(b'\x50\x52\x49\x20\x2a\x20\x48\x54\x54\x50\x2f\x32\x2e\x30\x0d\x0a\x0d\x0a\x53\x4d\x0d\x0a\x0d\x0a' + settings) # MAGIC

b = http2.recv_frame(conn)
settings_srv = http2.decode_any(b)
if type(settings_srv) != http2.frame_settings:
  assert False

hdrsz = 4096
max_frame = 16384
for setting in settings_srv.settings:
  if type(setting) == http2.setting_header_table_size:
    hdrsz = setting.val
  if type(setting) == http2.setting_max_frame_size:
    max_frame = setting.val
print "Using header size", hdrsz

print "1", repr(b)
print type(settings_srv)

#b = http2.recv_frame(conn)
#print "2", repr(b)
#a = http2.decode_any(b)
#print type(a)

#b = http2.recv_frame(conn)
#print "3", repr(b)
#a = http2.decode_any(b)
#print type(a)

print "Sending settings ACK"
settings = http2.encode_frame(http2.encode_settings([], 1))
conn.sendall(settings)

#print "Sending window update"
#conn.sendall(http2.encode_frame(http2.encode_window_update(0, 65536)))

hdrsendtbl = hpack.hdrtbl()

hdrs = hpack.encodesz(0) + hpack.encodehdrs([
  (':method', 'GET'),
  (':scheme', 'https'),
  (':path', '/'),
  #('host', hostname),
  (':authority', hostname),
  ('user-agent', 'curl/7.58.0'),
  ('accept', '*/*'),
], hdrsendtbl)
end_stream = 1
stream_id = 1
#conn.sendall(http2.encode_frame(http2.encode_headers(stream_id, 0, 0, 0, hdrs, end_stream, 0, 16384)[0]))
for frame in http2.encode_headers(stream_id, 0, 0, 0, hdrs, end_stream, 0, max_frame):
  conn.sendall(http2.encode_frame(frame))
#conn.sendall(http2.encode_frame(http2.encode_window_update(stream_id, 65535)))
#conn.sendall(http2.encode_frame(http2.encode_window_update(0, 65535)))

hdrtbl = hpack.hdrtbl()

print "LOOP"
while True:
  b = http2.recv_frame(conn)
  a = http2.decode_any(b)
  if type(a) == http2.frame_push_promise:
    pass
  elif type(a) == http2.frame_settings:
    for setting in a.settings:
      if type(setting) == http2.setting_header_table_size:
        hdrsz = setting.val
        print "Using header size", hdrsz
      if type(setting) == http2.setting_max_frame_size:
        max_frame = setting.val
        print "Using frame size", max_frame
  elif type(a) == http2.frame_headers:
    print "---", a.stream_id
    bs = hpack.bitstr(hdrsz, hdrtbl)
    bs.ar = bytearray(a.headers)
    while a.flags & 0x4 != 0x4:
      b = http2.recv_frame(conn)
      a = http2.decode_any(b)
      assert type(a) == http2.frame_continuation
      bs.ar += a.headers
    print len(bs.ar)
    while bs.readidx < len(bs.ar):
      hdr = hpack.hdrdecode(bs)
      if hdr:
        print hdr
    print "---"
  elif type(a) == http2.frame_data:
    print "DATA", a.data[:80]
    if a.flags & 0x1:
      break
    time.sleep(1)
    print "Sending window update for stream and connection"
    conn.sendall(http2.encode_frame(http2.encode_window_update(a.stream_id, len(a.data))))
    conn.sendall(http2.encode_frame(http2.encode_window_update(0, len(a.data))))
  elif type(a) == http2.frame_rst_stream:
    print "RST", a.stream_id, a.error_code
  else:
    print repr(b)
