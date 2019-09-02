__author__ = 'jmh081701'
##########################
##########
##########
#对实验结果进行验证的工具库
###########################
from  CMiddlebox_Inbound_Client import Replay_Client
from  Replay import  replay_client
from  python_lib import  randomize
from  Replay import  insert_packet,insert_payload
from config import  config
import  copy
def main(pcapname,packet_id,offset,length):
     client =Replay_Client(pcapname,pcap_client_ip=config['pcapname_client_ip'],replay_server_ip=config['outbound_ip'])
     stream = copy.deepcopy(client.stream)
     payload_index = stream['c2s']['meta'][packet_id]['payload_index']
     payload = stream['c2s']['payload'][payload_index]
     payload_modified = randomize(payload,offset,offset+length)
     stream['c2s']['payload'][payload_index]=payload_modified
     remote_port = client.requry_remote_port()
     ###Now replay!
     if replay_client(stream,client.replay_server_ip,remote_port,client.proto)==True:
         print('pass!!!!')
     else:
         print('block!!!')

if __name__ == '__main__':
    pcap_name=config['pcapname']
    packet_id = 0
    offset = 0
    length = 2
    main(pcap_name,packet_id,offset,length)
