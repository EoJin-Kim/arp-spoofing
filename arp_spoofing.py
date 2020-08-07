
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

def arp_broadcast(source_mac,source_ip,sender_ip):
    ################ ethernet header
    #print(s_mac)
    source_mac
    sender_mac=b'\x00\x00\x00\x00\x00\x00'
    d_mac=b'\xff\xff\xff\xff\xff\xff'
    arp_type=b'\x08\x06'
    #print(type(d_mac))
    eth=d_mac+source_mac+arp_type
    #print(len(eth))
    ################ arp_header
    # ethernet = 0x0001
    htype = b'\x00\x01'

    # IP =0x0800
    protype = b'\x08\x00'

    # H/W address Length
    hsize = b'\x06'

    # Protocol Address Length
    psize = b'\x04'

    # 0x001 request
    # 0x002 reply
    opcode = b'\x00\x01'

    source_ip=socket.inet_aton(source_ip)
    sender_ip=socket.inet_aton(sender_ip)
    #print(sender_ip)
    arp_broadcase_packet = eth + htype + protype + hsize + psize + opcode + source_mac+source_ip + sender_mac +sender_ip
    #print(len(arp_broadcase_packet))
    return arp_broadcase_packet
    
def arp_broadcast_send(ifname,my_mac,my_ip,sender_ip):
    # 0x0800 ETH_P_IP define
    s=socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0800))
    s.bind((ifname,socket.htons(0x0800)))
    my_arp=headers.arp_header(my_mac,my_ip,b'\xff\xff\xff\xff\xff\xff',sender_ip)
    my_arp.d_mac = b'\xff\xff\xff\xff\xff\xff'
    my_arp.s_mac=my_mac
    my_arp.eth_type=b'\x08\x06'
    #my_arp.arp_request()
    arp_broadcast_packet=my_arp.make_arp_packet()
    #s.send(arp_broadcast_packet)
    s.close()
def main():
    ifname = sys.argv[1]
    my_mac=get_mac(ifname)
    my_ip = get_my_ip(ifname)
    
    for i in range(2,argc,2):
        sender_ip=sys.argv[i]
        target_ip=sys.argv[i+1]
        arp_broadcast_send(ifname,my_mac,my_ip,sender_ip)
        #print(sys.argv[i])
        #print(sys.argv[i+1])
    #print(len(my_mac))
    #print(get_mac_string(my_mac))
    #print(my_ip)
    '''
    # 0x0800 ETH_P_IP define
    s=socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0800))
    s.bind((ifname,socket.htons(0x0800)))
    arp_broadcast_packet=arp_broadcast(my_mac,my_ip,sys.argv[2])
    #print(arp_broadcast_packet)
    s.send(arp_broadcast_packet)
    
    ss=socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0800))
    while True:
        #2048size buffer
        pkt=ss.recvfrom(2048)
        
        #print(pkt[0])
    return
    '''

if __name__ == "__main__":

    argc=len(sys.argv)
    #print(argc)
    #print(argc%2)
    if argc<4 or argc%2!=0:
        usage()

    main()