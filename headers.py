import socket


class ethernet_header:
    
    def __init__(self,d_mac,s_mac,eth_type,packet=None):
        self.d_mac=d_mac
        self.s_mac=s_mac
        self.eth_type=eth_type
        self.packet = packet
    def make_eth_packet(self,):

        self.ether_header_packet = self.d_mac+self.s_mac+self.eth_type
        return self.ether_header_packet

    def packet_parser(self,):
        return

class arp_header(ethernet_header):
    
    def __init__(self,source_mac,source_ip,destination_mac,destination_ip,packet=None):

        ################ arp_header
        # ethernet = 0x0001
        self.htype = b'\x00\x01'

        # IP =0x0800
        self.protype = b'\x08\x00'

        # H/W address Length
        self.hsize = b'\x06'

        # Protocol Address Length
        self.psize = b'\x04'

        # 0x001 request
        # 0x002 reply
        self.opcode = b''

        self.arp_s_mac=source_mac
        self.source_ip=socket.inet_aton(source_ip)

        self.arp_d_mac=destination_mac
        self.destination_ip=socket.inet_aton(destination_ip)

        self.packet=packet
    
    def arp_request(self):
        self.opcode = b'\x00\x01'

    def arp_reply(self):
        self.opcode = b'\x00\x02'



    def make_arp_packet(self):
        self.ether_header = self.make_eth_packet()
        print(len(self.ether_header))
        self.arp_header = self.htype + self.protype + self.hsize + self.psize + self.opcode \
            + self.arp_s_mac+self.source_ip + self.arp_d_mac +self.destination_ip
        self.arp_packet = self.ether_header+self.arp_header
        print(len(self.arp_header))
        print(len(self.arp_packet))
        #eturn self.arp_packet

    def packet_parser(self,):
        return
