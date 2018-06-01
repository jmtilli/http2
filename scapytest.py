from scapy.all import *
import http2
import hpack

pkts=[]
seq=1

def send(x):
  global seq
  pkts.append(Ether() / IP() / TCP(flags='A',seq=seq,sport=12345,dport=80) / x)
  seq += len(x)

send(b'\x50\x52\x49\x20\x2a\x20\x48\x54\x54\x50\x2f\x32\x2e\x30\x0d\x0a\x0d\x0a\x53\x4d\x0d\x0a\x0d\x0a')

settings = http2.encode_frame(http2.encode_settings([], 0))

send(settings)

hdrs = hpack.encodehdrs([
  (':method', 'GET'),
  (':scheme', 'https'),
  (':path', '/'),
  ('host', 'www.google.fi'),
  ('accept', 'text/html'),
], hpack.hdrtbl())
end_stream = 1
send(http2.encode_frame(http2.encode_headers(1, 0, 0, 0, hdrs, end_stream, 0, 16384)[0]))

wrpcap('http2.pcap', pkts)
