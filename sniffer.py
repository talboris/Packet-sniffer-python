
import socket
import struct
import binascii
import os


if os.name == 'nt':
    s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)
    s.bind(("192.168.1.12",0))
    s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
    s.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)
    recievedraw=s.recvfrom(65565)
else:
     s=socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
     recievedraw=s.recvfrom(65565)


class decodepack:
	def __init__(self):
		self.data=self
		
	def etherpacket(self,data):
		rawpacket=data
		#packet=struct.unpack("!6s6sH",rawpacket)
		src_mac,dest_mac,eth_type=struct.unpack("!6s6sH",rawpacket)
		
		#src_mac=binascii.hexlify(packet[0])
		#dest_mac=binascii.hexlify(packet[1])
		#eth_type=packet[2]
		return src_mac, dest_mac,eth_type
	#a.etherpacket(recievedraw[][14:34])
	def ip_packet(self,data):
	    rawpacket=data
	    protocol,source_ip, dest_ip=struct.unpack("!9x B 2x 4s 4s",rawpacket[:20])
	    print('---------------IP DETAILS--------------------------------------------------\n\n')
	    
	    print("The source IP is:\t\t{}\n\n".format(socket.inet_ntoa(source_ip)))
	    print("The destination IP is:\t\t{}\n\n".format(socket.inet_ntoa(dest_ip)))
	    #print(socket.inet_ntoa(dest_ip))
	    if protocol is 6:
	        print("PROTOCOL IS TCP ")
	    #print(protocol)
	    return 

def mac_format_layout(var):
    
    
    src_mac=(map('{:02x}'.format, var))
   
    src_mac2=":".join(src_mac)
   
    return src_mac2
    
while True:    
    a=decodepack()
    src_mac,dest_mac,eth_type=a.etherpacket(recievedraw[0][:14])
    src_mac_for_print=mac_format_layout(src_mac)
    dest_mac_for_print=mac_format_layout(dest_mac)
    print("--------source mac---------------------------\n\r")
    print(src_mac_for_print)
    print("---------------------------------------------\n\r")
    print("--------destination mac----------------------\n\r")
    print(dest_mac_for_print)
    print("---------------------------------------------\n\r")
    print("\n\n")
    print("type of eth is:\t\t\t\t\n")
    print(hex(eth_type))
    print("\n\n")
    print("\n\n")
    a.ip_packet(recievedraw[0][14:])
    os.system('clear')
    
    
'''

def pro(self,data):
    return




while True:
	b=a.etherpacket(recievedraw[0][:14])
	
    print(src_mac_formatted)
	print(packet2)
	print(hex(packet3))

'''
