__author__ = 'dk'
from hash import  hash_int
import python_lib
import  socket
class ReplayDator():
    #################################
    ###########
    ###########
    #   数据提取类,主要从pcap里面提取流
    #################################
    def __init__(self,pcapname,pcap_client_ip):
        #   pcap_client_ip 是抓取的原始pcap里面,主动向外发起请求的ip 地址,这个一般就是客户端IP
        #   重放的数据流
        self.stream = python_lib.extractStream(pcapname,pcap_client_ip)
        self.client_packets_id=set()    #客户端需要发送的数据包的id号
        self.server_packets_id=set()    #服务端需要发送的数据的id号
        self.server_payload_hash_to_id={}
        self.client_payload_hash_to_id={}
        self.payload_hash_to_id={}
        for each in self.stream['c2s']:
            hash_value =hash_int(each['payload'])
            self.client_payload_hash_to_id[hash_value] = each['id']
            self.payload_hash_to_id[hash_value]=each['id']
            self.client_packets_id.add(each['id'])

        for each in self.stream['s2c']:
            hash_value = hash_int(each['payload'])
            self.server_payload_hash_to_id[hash_value]=each['id']
            self.payload_hash_to_id[hash_value]=each['id']
            self.server_packets_id.add(each['id'])
class Replay:
    def __init__(self,pcapname,pcap_client_ip):
        #pcap_client_ip 是抓取的原始pcap里面,主动向外发起请求的ip 地址,这个一般就是客户端IP
        #重放的数据流
        self.stream = python_lib.extractStream(pcapname,pcap_client_ip)
        self.client_packets_id=set()    #客户端需要发送的数据包的id号
        self.server_packets_id=set()    #服务端需要发送的数据的id号
        self.server_payload_hash_to_id={}
        self.client_payload_hash_to_id={}
        self.payload_hash_to_id={}
        for each in self.stream['c2s']:
            hash_value =hash_int(each['payload'])
            self.client_payload_hash_to_id[hash_value] = each['id']
            self.payload_hash_to_id[hash_value]=each['id']
            self.client_packets_id.add(each['id'])

        for each in self.stream['s2c']:
            hash_value = hash_int(each['payload'])
            self.server_payload_hash_to_id[hash_value]=each['id']
            self.payload_hash_to_id[hash_value]=each['id']
            self.server_packets_id.add(each['id'])

def replay_client(_stream,remote_ip,remote_port,proto):
    ############
    ######
    ######
    #给定一组_stream(里面有c2s,也有s2c),然后对这组数据进行重放,看能否重放完整个流
    #返回值,应该是true/false(true表示整个流程都重放完整,false表示中途就被拦截)
    ############
    rst = True
    client_ids = {1}
    stream = _stream['c2s']
    for each in stream:
        client_ids.add(each['id'])
    current_id = 1
    current_curse = 0
    recv_ids=set()
    send_ids=set()
    sock = python_lib.SOCKET(proto,'client',remote_ip,remote_port)
    try:
        while True:
            action = False
            while current_id in client_ids:
                payload = stream[current_curse]['payload']
                sock.send(payload)
                send_ids.add(current_id)
                current_curse =current_curse +1
                current_id += 1
                action = True
            while current_id not in client_ids:
                data = sock.recv(len(_stream['payload'][current_id]))
                print('recv %d'%current_id)
                recv_ids.add(current_id)
                current_id += 1
                action = True
            if action==False:
                break
    except:
        pass
    if current_id==len(_stream['payload'])-1:
        rst = True
    try:
        sock.socket.shutdown(2)
        sock.close()
    except :
        pass
    return rst
def is_port_used(ip,port,proto):
    if proto=='TCP':
        proto = socket.SOCK_STREAM
    elif proto=='UDP':
        proto=socket.SOCK_DGRAM
    s=socket.socket(socket.AF_INET,type=proto)
    try:
        s.connect((ip,port))
        s.shutdown(2)
        return True
    except OSError:
        return False
    finally:
        s.close()
def replay_server(_stream,local_ip="0.0.0.0",local_port=0):
    stream = _stream['s2c']
    proto = stream[0]['proto']
    server_ids = set()
    for each in stream:
        server_ids.add(each['id'])
    current_id = 1
    current_curse = 0
    recv_ids = set()
    send_ids = set()
    sock = python_lib.SOCKET(proto,'server',local_ip,local_port)
    try:
        while True:
            action = False
            while current_id not in server_ids:
                data = sock.recv(len(_stream['payload'][current_id]))
                print('recv %d'%current_id)
                recv_ids.add(current_id)
                current_id += 1
                action=True
            while current_id in server_ids:
                payload=stream[current_curse]['payload']
                sock.send(payload)
                print('send %d'%current_id)
                send_ids.add(current_id)
                current_curse = current_curse + 1
                current_id += 1
                action = True
            if action==False:
                break
                #已经没有任何动作了
        #sock.socket.shutdown(2)
        sock.socket.close()
    except:
        pass

