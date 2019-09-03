__author__ = 'dk'
import  os
import argparse
import shutil
def extract_stream(pcap_file,pcap_folder,client_ip,proto):
    #首先提取获取流的id
    stream_number = set()
    command = 'tshark -2 -r {0} -T fields -e {1}.stream "ip.addr=={2}"| sort -n'.format(pcap_file,proto,client_ip)
    print(command)
    proc =os.popen(command)
    result = proc.readlines()
    for each in result:
        each = each.strip()
        if each.isdecimal():
           stream_number.add(int(each))
    #对于每一条流,保存它的pcap
    for each in stream_number:
        command = 'tshark -2 -r {0} -R {1}.stream=={2} -w {3}'.format(pcap_file,proto,each,pcap_folder+"//"+proto+"_stream"+str(each)+".pcap")
        proc = os.popen(command).readlines()
        #proc.close()

def main(pcap_file,pcap_folder,client_ip):
    no_Retrans_pcap_file = pcap_file.split(".pcap")[0]+"noRet.pcap"
    command='tshark -2 -R "not tcp.analysis.retransmission && not tcp.analysis.out_of_order" -r {0} -w {1}'.format(pcap_file,no_Retrans_pcap_file)
    os.popen(command).readlines()
    extract_stream(no_Retrans_pcap_file,pcap_folder,client_ip,'tcp')
    extract_stream(no_Retrans_pcap_file,pcap_folder,client_ip,'udp')
    if os.path.exists(no_Retrans_pcap_file):
        os.remove(no_Retrans_pcap_file)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract tcp/udp stream from pcap file.')
    parser.add_argument('--pcap_file',type=str,help='The raw pacp filename.',required=True)
    parser.add_argument('--pcap_folder',type=str,required=False,help='The destination folder to store the stream,default is the name of pcap file',default="")
    parser.add_argument('--client_ip',type=str,required=True,help='The ip address of this stream,which is concerned')
    args = parser.parse_args()
    if args.pcap_folder=="":
        args.pcap_folder =".//"+args.pcap_file.split(".pcap")[0]
    if os.path.exists(args.pcap_folder):
        shutil.rmtree(args.pcap_folder,ignore_errors=True)
    os.mkdir(args.pcap_folder)
    main(args.pcap_file,args.pcap_folder,args.client_ip)
