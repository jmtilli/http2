import socket
import re
import http11
import http2
import base64

ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ss.bind(('0.0.0.0', 8080))
ss.listen(1)
s, addr = ss.accept()

data = ""
while True:
  data += s.recv(1024)
  if not data:
    break
  if '\r\n\r\n' in data:
    print data
    break
head = data[:data.find('\r\n\r\n')]
remain = data[data.find('\r\n\r\n'):]
lines = head.split('\r\n')
reqln = lines[0].split(' ')
assert len(reqln) == 3
print "Method", reqln[0]
print "URI", reqln[1]
if reqln[2][:5] != "HTTP/":
  assert False
majminv = reqln[2][5:].split('.')
if len(majminv) != 2:
  assert False
majv,minv = majminv
if majv != '1':
  assert False
if minv != '1':
  assert False

headersdict = http11.parse_headers(lines[1:])

print ""

if "Host" in headersdict:
  print "Host: " + headersdict["Host"]
if "Connection" in headersdict:
  print "Connection: " + headersdict["Connection"]
if "Upgrade" in headersdict:
  print "Upgrade: " + headersdict["Upgrade"]
if "HTTP2-Settings" in headersdict:
  print "HTTP2-Settings: " + headersdict["HTTP2-Settings"]

def base64_nonequals(s):
  for n in range(10):
    try:
      return base64.urlsafe_b64decode(s)
    except Exception:
      s += "="
  raise Exception("encoding error")

settings = base64_nonequals(headersdict["HTTP2-Settings"])
print "Settings decoded: " + settings
  
resp = ""
resp += 'HTTP/1.1 101 Switching Protocols\r\n'
resp += 'Connection: Upgrade\r\n'
resp += 'Upgrade: h2c\r\n'
resp += '\r\n'

s.send(resp)

s.close()
