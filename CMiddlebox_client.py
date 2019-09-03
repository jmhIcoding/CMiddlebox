__author__ = 'dk'
import  python_lib
import  requests
from  binary_op import  randomize
stream = python_lib.extractStream("Youtube_no_retransmits.pcap",client_ip="172.20.161.222")['c2s']
if stream[0]['proto']=='TCP':
    SOCK = python_lib.SOCKET('TCP','client',ip='47.254.71.134',port=stream[0]['dst_port'])
elif stream[0]['proto']=='UDP':
    SOCK = python_lib.SOCKET('UDP','client',ip='47.254.71.134',port=stream[0]['dst_port'])
client_ids = {1}
for each in stream:
    client_ids.add(each['id'])
current_id = 1
current_curse = 0

recv_ids=set()
send_ids=set()
def feed_back(id):
    url='http://47.254.71.134:8000/cmiddlebox'
    #url='http://127.0.0.1:8000/cmiddlebox'
    jdata = {'id':id}
    reponse=requests.post(url,json=jdata)
    print(reponse.json())
    return reponse.json()['result']
while True:
    while current_id in client_ids:
        payload=stream[current_curse]['payload']
        payload = randomize(payload,0,len(payload))
        SOCK.send(payload)
        send_ids.add(current_id)
        current_curse =current_curse +1
        if feed_back(current_id)==False:
            #失败
            pass
        else:
            #连接成功
            pass
        current_id +=1
    while current_id not in client_ids:
        data = SOCK.recv(4096)
        print('recv %d'%current_id)
        recv_ids.add(current_id)
        current_id +=1