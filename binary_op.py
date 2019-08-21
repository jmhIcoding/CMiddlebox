__author__ = 'dk'
#二进制操作库
import  struct
def randomize(payload,start,end,method='invert'):
    if isinstance(payload,bytes):
        payload = bytearray(payload)
    if method =='invert':
        for i in range(start,end):
            payload[i] = ~payload[i] % 256
    if method =='rand':
        for i in range(start,end):
            payload[i] = random.randint()%256
    return bytes(payload)