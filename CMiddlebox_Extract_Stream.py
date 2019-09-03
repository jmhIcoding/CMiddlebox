__author__ = 'dk'
import  sys
import  os
import  subprocess
import argparse
def extract_stream(pcap_file,pcap_folder,client_ip,proto):
    #首先提取获取流的id
    stream_number = set()
    command = 'tshark -2 -r {0} -T fields -e {1}.stream "ip.address=={2}"| sort -n'.format(pcap_file,proto,client_ip)
    proc =os.popen(command)
    result = proc.readlines()
    proc.close()
    for each in result:
        stream_number.add(int(each))
    #对于每一条流,保存它的pcap
    for each in stream_number:
        command = 'tshark -2 -r {0} -R {1}.stream=={2} -w {3}'.format(pcap_file,proto,each,pcap_folder+"//"+proto+"_stream"+str(each)+".pcap")
        proc = os.popen(command).readlines()
        proc.close()

def main(pcap_file,pcap_folder,client_ip):
    extract_stream(pcap_file,pcap_folder,client_ip,'tcp')
    extract_stream(pcap_file,pcap_file,client_ip,'udp')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract tcp/udp stream from pcap file.')
    parser.add_argument('--pcap_file',type=str,help='The raw pacp filename.')
    parser.add_argument('--pcap_folder',type=str,help='The destination folder to store the stream,default is the name of pcap file',default="")
    parser.add_argument('--client_ip',type=str,help='The ip address of this stream,which is concerned')
    args = parser.parse_args()
    if args.pcap_folder=="":
        args.pcap_folder =".//"+args.pcap_file
    if os.path.exists(args.pcap_folder):
        os.rmdir(args.pcap_folder)
    os.mkdir(args.pcap_folder)
    main(args.pcap_file,args.pcap_folder,args.client_ip)