__author__ = 'jmh081701'
##########################
##########
##########
#对实验结果进行验证的工具库
###########################
from  CMiddlebox_Inbound_Client import Replay_Client
from  Replay import  replay_client
from  python_lib import  randomize
from config import  config
def main(pcapname,packet_id,offset,length):
     client =Replay_Client(pcapname,pcap_client_ip=config['pcapname_client_ip'],replay_server_ip=config['outbound_ip'])
     payload = client.stream['c2s'][packet_id]
     payload_modified = randomize(payload,offset,offset+end)
     client.stream['c2s'][packet_id]=payload
     remote_port = client.request_remote()
     ###Now replay!
     if replay_client(client.stream,client.replay_server_ip,remote_port,client.proto)==True:
         print('pass!!!!')
     else:
         print('block!!!')
if __name__ == '__main__':
    pcap_name=config['pcapname']
    packet_id = 0
    offset = 0
    length = 2
    main(pacp_name,packet_id,offset,length)
