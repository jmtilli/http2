import socket
import ssl
import hpack
import http2
#from scapy.all import *

sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('', 8443))
sock.listen(5)

def drain():
  global window_conn
  global window_stream
  global conn
  global global_stream_id
  while tosends:
    if len(tosends[0].payload) > window_conn:
      break
    if len(tosends[0].payload) > window_stream[tosends[0].stream_id]:
      break
    conn.sendall(http2.encode_frame(tosends[0]))
    window_conn -= len(tosends[0].payload)
    window_stream[tosends[0].stream_id] -= len(tosends[0].payload)
    del tosends[0]

while True:
  context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
  context.set_alpn_protocols(['h2'])
  context.check_hostname = False
  context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
  context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20")
  context.options |= ssl.OP_NO_COMPRESSION
  context.options |= (
    ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
  )
  
  tcp_conn = sock.accept()[0]
  #
  tosends = []
  #
  initial_window = 65535
  window_conn = 65535
  window_stream = {}
  #
  conn = context.wrap_socket(tcp_conn, server_side=True)
  print(conn.selected_alpn_protocol())
  
  try:
    data = http2.recvall(conn,len(b'\x50\x52\x49\x20\x2a\x20\x48\x54\x54\x50\x2f\x32\x2e\x30\x0d\x0a\x0d\x0a\x53\x4d\x0d\x0a\x0d\x0a'))
    if data != b'\x50\x52\x49\x20\x2a\x20\x48\x54\x54\x50\x2f\x32\x2e\x30\x0d\x0a\x0d\x0a\x53\x4d\x0d\x0a\x0d\x0a':
      assert False
  except ssl.SSLError:
    continue
  
  settings = http2.encode_frame(http2.encode_settings([
    http2.setting_header_table_size(8192),
  ], 0))
  conn.sendall(settings)
  
  hdrtbl = hpack.hdrtbl()
  enctbl = hpack.hdrtbl()
  
  hdrsz = 4096
  
  print "LOOP"
  while True:
    b = http2.recv_frame(conn)
    if len(b) == 0:
      break
    a = http2.decode_any(b)
    if type(a) == http2.frame_push_promise:
      assert False
    elif type(a) == http2.frame_settings:
      for setting in a.settings:
        if type(setting) == http2.setting_header_table_size:
          hdrsz = setting.val
          print "Using header size", hdrsz
        if type(setting) == http2.setting_initial_window_size:
          newval = setting.val
          diff = newval - initial_window
          initial_window += diff
          window_conn += diff
          for k in window_stream:
            window_stream[k] += diff
          print "Using window size", newval
      if not (a.flags & 0x1):
        settings = http2.encode_frame(http2.encode_settings([], 1))
        conn.sendall(settings)
        print "SETTINGS"
      else:
        print "SETTINGS ACK"
    elif type(a) == http2.frame_headers:
      #pkts=[]
      #seq=1
      #def send(x):
      #  global seq
      #  pkts.append(Ether() / IP() / TCP(flags='A',seq=seq,sport=12345,dport=80) / x)
      #  seq += len(x)
      #send(b'\x50\x52\x49\x20\x2a\x20\x48\x54\x54\x50\x2f\x32\x2e\x30\x0d\x0a\x0d\x0a\x53\x4d\x0d\x0a\x0d\x0a')
      #send(b)
      #wrpcap('httpsrv.pcap', pkts)
      #
      window_stream[a.stream_id] = initial_window
      print "---", a.stream_id
      bs = hpack.bitstr(hdrsz, hdrtbl)
      bs.ar = bytearray(a.headers)
      while a.flags & 0x4 != 0x4:
        b = http2.recv_frame(conn)
        a = http2.decode_any(b)
        assert type(a) == http2.frame_continuation
        bs.ar += a.headers
      print len(bs.ar)
      d = {}
      print repr(bs.ar)
      while bs.readidx < len(bs.ar):
        hdr = hpack.hdrdecode(bs)
        if hdr:
          print hdr
          d[hdr[0]] = hdr[1]
        else:
          print "Update"
      print "---"
      if ":method" not in d:
        assert False
      if d[":method"] != "GET":
        assert False
      if ":scheme" not in d:
        assert False
      if d[":scheme"] != "https":
        assert False
      if ":path" not in d:
        assert False
      if d[":path"] != "/":
        assert False
      hdrs = [
        (':status', '200'),
        ('server', 'custom prototype'),
      ]
      hdrstr = hpack.encodehdrs(hdrs, enctbl)
      #for frame in http2.encode_headers(a.stream_id, 0, 0, 0, hdrstr, 0, 0, 16384): # FIXME sz
      for frame in http2.encode_headers(a.stream_id, 0, 0, 0, hdrstr, 0, 0, 1): # FIXME sz
        conn.sendall(http2.encode_frame(frame))
      #tosends = http2.encode_data(a.stream_id, 'Foo', 1, 16384) # FIXME sz
      tosends = http2.encode_data(a.stream_id, 'Foo', 1, 1) # FIXME sz
      print "Draing"
      drain()
      print "Drained"
    elif type(a) == http2.frame_window_update:
      if a.stream_id > 0:
        window_stream[a.stream_id] += a.increment
      else:
        window_conn += a.increment
      drain()
    elif type(a) == http2.frame_data:
      print "DATA", a.data[:80]
      if a.flags & 0x1:
        break
      print "Sending window update for stream and connection"
      conn.sendall(http2.encode_frame(http2.encode_window_update(a.stream_id, len(a.data))))
      conn.sendall(http2.encode_frame(http2.encode_window_update(0, len(a.data))))
    elif type(a) == http2.frame_rst_stream:
      print "RST", a.stream_id, a.error_code
    else:
      print repr(b)
