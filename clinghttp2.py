import socket
import base64
import http11
import http2

domain = "www.google.fi"

hdrs = ""
hdrs += "GET / HTTP/1.1\r\n"
hdrs += "Host: "+domain+"\r\n"
hdrs += "Connection: Upgrade, HTTP2-Settings\r\n"
hdrs += "Upgrade: h2c\r\n"
settings = http2.encode_frame(http2.encode_settings([], 0))
settings = base64.urlsafe_b64encode(settings)
settings = settings.replace('=', '')
hdrs += "HTTP2-Settings: " + settings + "\r\n"
hdrs += "\r\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((domain, 80))
s.send(hdrs)

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
respln = lines[0].split(' ', 2)
print respln
assert len(respln) == 3
if respln[0][:5] != "HTTP/":
  assert False
majminv = respln[0][5:].split('.')
if len(majminv) != 2:
  assert False
majv,minv = majminv
if majv != '1':
  assert False
if minv != '1':
  assert False
headers = lines[1:]
print "Status", int(respln[1])
print "HR-Status", respln[2]

print ""

headersdict = http11.parse_headers(headers)
if "Connection" in headersdict:
  print "Connection: " + headersdict["Connection"]
if "Upgrade" in headersdict:
  print "Upgrade: " + headersdict["Upgrade"]

s.close()
