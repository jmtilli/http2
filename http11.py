def parse_headers(headers):
  headersparsed = []
  for h in headers:
    if h[0] == ' ' or h[0] == '\t':
      headersparsed[-1] = (headersparsed[-1][0], headersparsed[-1][1] + h[1:])
    else:
      sp = h.split(':', 1)
      headersparsed.append((sp[0], sp[1]))
  headersparsed2 = []
  headersdict = {}
  for key,value in headersparsed:
    n = 0
    while n < len(value) and (value[n] == ' ' or value[n] == '\t'):
      n += 1
    value = value[n:]
    m = len(value)
    while m > 0 and (value[m-1] == ' ' or value[m-1] == '\t'):
      m -= 1
    value = value[:m]
    if key in headersdict:
      headersdict[key] = headersdict[key] + ", " + value
    else:
      headersdict[key] = value
    headersparsed2.append((key, value))
  return headersdict
