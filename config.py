#coding:utf-8
__author__ = 'jmh081701'
import  json
config = {
        'inbound_port':9901,
        'outbound_port':9900,
        'outbound_create_new_channel':"/api/cmiddle/newchannel",
        'outbound_ip':'10.0.0.2',
        'outbound_url':'/api/cmiddle/outbound',
        'outbound_next_packet_url':'/api/cmiddle/npacket',
        'mongodb_ip':'172.16.30.180',
        'mongodb_username':'s9',
        'mongodb_pwd':'123456',
        'mongodb_dbname':'CMiddlebox',
        'mongodb_port':'27017',
        'pcapname':'Youtube_no_retransmits.pcap',
        'pcapname_client_ip':"172.20.161.222"
        }
