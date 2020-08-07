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

    def ethernet_parser(self,):
        self.d_mac=self.packet[0:6]
        self.s_mac=self.packet[6:12]
        return

class arp_header(ethernet_header):
    
    def __init__(self,sender_mac=None,sender_ip=None,target_mac=None,target_ip=None,packet=None):

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

        self.sender_mac=sender_mac
        if sender_ip:
            self.sender_ip=socket.inet_aton(sender_ip)
        else:
            self.sender_ip=sender_ip

        self.target_mac=target_mac        
        if target_ip:
            self.target_ip=socket.inet_aton(target_ip)
        else:
            self.target_ip=target_ip

        self.packet=packet
    
    def arp_request(self):
        self.opcode = b'\x00\x01'

    def arp_reply(self):
        self.opcode = b'\x00\x02'



    def make_arp_packet(self):
        self.ether_header = self.make_eth_packet()
        #print(len(self.ether_header))
        self.arp_header = self.htype + self.protype + self.hsize + self.psize + self.opcode \
            + self.sender_mac+self.sender_ip + self.target_mac +self.target_ip
        self.arp_packet = self.ether_header+self.arp_header
        #print(len(self.arp_header))
        #print(len(self.arp_packet))
        return self.arp_packet

    def arp_parser(self,):
        self.ethernet_parser()
        

        self.sender_mac=self.packet[0x16:0x1c]

        self.sender_ip=self.packet[0x1c:0x20]

        self.target_mac=self.packet[0x20:0x26]
       
        self.target_ip=self.packet[0x26:0x2a]
        return
