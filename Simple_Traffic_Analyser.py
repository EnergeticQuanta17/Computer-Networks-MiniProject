import time
import pyshark

capture=pyshark.LiveCapture(interface='Wi-Fi',bpf_filter='tcp')
def capture_packets_filter_flags(req_flags): # parameter is string with exact order URG,ACK,PSH,SYN,FIN
    packet=0
    for packet in capture.sniff_continuously():
        tcp_live=packet.layers
        ind=0
        for layer in packet.layers:
            if(layer.layer_name=='tcp'):
                tcp_live=(packet.layers)[ind]
                break
            ind+=1

        all_flags=str(str(tcp_live.get_field('tcp.flags.urg'))+
                      str(tcp_live.get_field('tcp.flags.ack'))+
                      str(tcp_live.get_field('tcp.flags.push'))+
                      str(tcp_live.get_field('tcp.flags.syn'))+
                      str(tcp_live.get_field('tcp.flags.fin')))
        if(all_flags==req_flags):
            #print('Woo, another packet:', packet.tcp.flags)
            print(' '*15,end='')
            print("PACKET NUMBER:",packet.number,end='\n\n')
            
            print("Time: ",' '*25,packet.sniff_time)
            print()
            
            print("Packet Length:",' '*17,packet.length)
            
            print("Source Port: ",' '*18,tcp_live.get_field('tcp.srcport'))
            print("Destination Port: ",' '*13,tcp_live.get_field('tcp.dstport'))
            print()
            print("Acknowledgement Number: ",' '*7,tcp_live.get_field('tcp.ack'))
            print("Acknowledgement Number (raw): ",' '*1,tcp_live.get_field('tcp.ack_raw'))
            print("Sequence Number: ",' '*14,tcp_live.get_field('tcp.seq'))
            print("Sequence Number (raw): ",' '*8,tcp_live.get_field('tcp.seq_raw'))
            print()
            print("URG Flag: ",tcp_live.get_field('tcp.flags.urg'))
            print("ACK Flag: ",tcp_live.get_field('tcp.flags.ack'))
            print("PSH Flag: ",tcp_live.get_field('tcp.flags.push'))
            print("SYN Flag: ",tcp_live.get_field('tcp.flags.syn'))
            print("FIN Flag: ",tcp_live.get_field('tcp.flags.fin'))

                  
            print("----------------------------------------------")
        ##    print(packet)
        ##    break
        ##
        ##

if __name__=='__main__':
    print("TCP TRAFFIC ANALYSER")
    print("Flags:-")
    print("1. U to set Urgent flag")
    print("2. A to set Acknowledgement flag")
    print("3. P to set Push flag")
    print("4. S to set Synchronization flag")
    print("5. F to set Finish flag",end='\n\n')
    
    str_flag=input("Enter the flags to display traffic: ")
    num_flags=0
    for i in str_flag:
        if(i=='U'):
            num_flags+=10**4
        if(i=='A'):
            num_flags+=10**3
        if(i=='P'):
            num_flags+=10**2
        if(i=='S'):
            num_flags+=10**1
        if(i=='F'):
            num_flags+=1
    num_flags='0'*(5-len(str(num_flags)))+str(num_flags)
    print(num_flags)
    capture_packets_filter_flags(num_flags)
    
        
        
        
        
            
    

