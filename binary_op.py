__author__ = 'dk'
#二进制操作库
import  struct
def byte2ansic(payload):
    s=[]
    if isinstance(payload,bytes):
        payload = bytearray(payload)
    for each in payload:
        s.append(chr(int(each)))
    return  "".join(s)
def byte2hex(payload):
    s=[]
    if isinstance(payload,bytes):
        payload = bytearray(payload)
    for each in payload:
        s.append(hex(each))
    return  "".join(s)
def randomize(payload,start,end,method='invert'):
    if isinstance(payload,bytes):
        payload = bytearray(payload)
    if not isinstance(payload,bytearray):
        raise Exception("payload should bytes or bytearray object. however %s received"%type(payload))
    if method =='invert':
        for i in range(start,end):
            payload[i] = ~payload[i] % 256
    if method =='rand':
        for i in range(start,end):
            payload[i] = random.randint()%256
    return bytes(payload)