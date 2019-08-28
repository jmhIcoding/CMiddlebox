__author__ = 'dk'
def hash_int(payload):
    if isinstance(payload,bytes):
        payload = bytearray(payload)
    if not isinstance(payload,bytearray):
        raise Exception("hash_int(payload):payload should bytes or bytearray object. however %s received"%type(payload))
    MOD=1e9+7
    P=19950817
    h = 1
    for i in range(0,len(payload)):
        h =( h *P + payload[i]) % MOD
    return int(h)
if __name__ == '__main__':
    print(hash_int('123456'))
