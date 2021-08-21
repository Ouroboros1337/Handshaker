#before use create iptable rule with
#sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

import socket
import sys
import binascii
import argparse
import struct
import ctypes
from struct import *
import array
from time import sleep

def ip_checksum(ip_header, size):
    
    cksum = 0
    pointer = 0
    
    #The main loop adds up each set of 2 bytes. They are first converted to strings and then concatenated
    #together, converted to integers, and then added to the sum.
    while size > 1:
        cksum += int((str("%02x" % (ip_header[pointer],)) + 
                      str("%02x" % (ip_header[pointer+1],))), 16)
        size -= 2
        pointer += 2
    if size: #This accounts for a situation where the header is odd
        cksum += ip_header[pointer]
        
    cksum = (cksum >> 16) + (cksum & 0xffff)
    cksum += (cksum >>16)
    return (~cksum) & 0xFFFF

def split_header2byteshex(s):
	i = 0
	j = 0
	res={}
	tmp=''
	if len(s)%2==0:
		s=s+"00"
	for char in s:
		if j==0:
			j=1
			tmp=char
		else:
			j=0
			tmp=tmp+char
			res[i]=int(tmp,16)
			i=i+1
	return res

parser = argparse.ArgumentParser(
    description='This program performes a custom TCP Handshake'
)
parser.add_argument('-dIP', metavar='destinationIP', required=True, help='The destination IP')
parser.add_argument('-dPort',  metavar='destinationPort', required=True, help='The destination Port')
parser.add_argument('-sIP',  metavar='sourceIP', required=True, help='The source IP')
parser.add_argument('-sPort',  metavar='sourcePort', required=True, help='sourcePort')
args = parser.parse_args()

dIP=bytes(map(int, args.dIP.split('.')))
sIP=bytes(map(int, args.sIP.split('.')))

dPort=struct.pack(">H",int(args.dPort))
sPort=struct.pack(">H",int(args.sPort))

tcppayload="Initial"#This is the payload data
iphlength=(len(tcppayload)+40).to_bytes(1,'big')

#change your custom ip flags and co here
ipvitle=b'\x45\x00\x00'+iphlength 	# Version, IHL, Type of Service | Total Length
ipidffo=b'\x00\x01\x40\x00' 		# Identification | Flags, Fragment Offset
ipttlpt=b'\x40\x06'			# TTL, Protocol
ipcs=b'\x00\x00'			# Dummy IP Checksum

#change your custom tcpflags and co here
tcpseq=b'\x00\x00\x00\x00'	# Initial Sequence Number
tcpackn=b'\x00\x00\x00\x00'	# Initianal Acknowledgement Number
tcpdorfws=b'\x50\x02\x20\x00'	# Data Offset, Reserved, Flags | Window Size
tcpup=b'\x00\x00'		# Urgent Pointer
tcpcs=b'\x00\x00'		# Dummy TCP Checksum

#calculating ip checksum 0xbaaf
data  = ipvitle
data += ipidffo 
data += ipttlpt 
data += ipcs
data +=sIP
data += dIP	
res=split_header2byteshex(data.hex())		
ipcs=ip_checksum(res,len(res)).to_bytes(2,'big')

#calculating tcp checksum
data  = sIP
data += dIP
data += b'\x00\x06' # tcpprotocol
data += b'\x00' +(len(tcppayload)+20).to_bytes(1,'big') #length
data += sPort
data += dPort
data += tcpseq
data += tcpackn
data += tcpdorfws
data += tcpcs
data += tcpup
data += bytes(tcppayload, 'utf-8')


res=split_header2byteshex(data.hex())		
tcpcs=ip_checksum(res,len(res)).to_bytes(2,'big')

data=bytes(tcppayload, 'utf-8')

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

ip_header  = ipvitle 			# Version, IHL, Type of Service | Total Length
ip_header += ipidffo 			# Identification | Flags, Fragment Offset
ip_header += ipttlpt + ipcs  		# TTL, Protocol | Header Checksum
ip_header += sIP  			# Source Address
ip_header += dIP  			# Destination Address

tcp_header  = sPort + dPort 		# Source Port | Destination Port
tcp_header += tcpseq 			# Sequence Number
tcp_header += tcpackn 			# Acknowledgement Number
tcp_header += tcpdorfws 		# Data Offset, Reserved, Flags | Window Size
tcp_header += tcpcs + tcpup 		# Checksum | Urgent Pointer

packet = ip_header + tcp_header + data
s.sendto(packet, (args.dIP, 0))
print("Sending: " +packet.hex())
s.close()

# receive response
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
while True:
  packet = s.recvfrom(65565)
  #packet string from tuple
  packet = packet[0]
  #take first 20 characters for the ip header
  ip_header = packet[0:20]
  #now unpack them :)
  iph = unpack('!BBHHHBBH4s4s' , ip_header)

  if bytes(map(int, socket.inet_ntoa(iph[8]).split('.')))==dIP:	
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iph_length = ihl * 4
    ttl = iph[5]
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8]);
    d_addr = socket.inet_ntoa(iph[9]);

    tcp_header = packet[iph_length:iph_length+20]
	
    #now unpack them :)
    tcph = unpack('!HHLLBBHHH' , tcp_header)
	
    source_port = tcph[0]
    dest_port = tcph[1]
    sequence = tcph[2]
    acknowledgement = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
	
  
    h_size = iph_length + tcph_length * 4
    data_size = len(packet) - h_size
    #get data from the packet
    data = packet[h_size:]
    
    #building a custom tcp tresponse u can modify your own flags and co below
    #it will use the ack and sequencenumber from above
    tcpseq=(acknowledgement+1).to_bytes(4, 'big')
    tcpackn=(sequence+1).to_bytes(4, 'big')
    
    tcppayload="Response"#This is the payload data for the response
    iphlength=(len(tcppayload)+40).to_bytes(1,'big')
    #change your custom ip flags and co here
    ipvitle=b'\x45\x00\x00' +iphlength	# Version, IHL, Type of Service | Total Length
    ipidffo=b'\x00\x01\x40\x00' 	# Identification | Flags, Fragment Offset
    ipttlpt=b'\x40\x06'		# TTL, Protocol
    ipcs=b'\x00\x00'		# Dummy IP Checksum

    #change your custom tcpflags and co here
    tcpdorfws=b'\x50\x10\x20\x00'	# Data Offset, Reserved, Flags | Window Size
    tcpup=b'\x00\x00'		# Urgent Pointer
    tcpcs=b'\x00\x00'		# Dummy TCP Checksum

    #calculating ip checksum 0xbaaf
    data  = ipvitle
    data += ipidffo 
    data += ipttlpt 
    data += ipcs
    data +=sIP
    data += dIP	
    res=split_header2byteshex(data.hex())		
    ipcs=ip_checksum(res,len(res)).to_bytes(2,'big')

    #calculating tcp checksum
    data  = sIP
    data += dIP
    data += b'\x00\x06' # tcpprotocol
    data += b'\x00'+ (len(tcppayload)+20).to_bytes(1,'big') #length
    data += sPort
    data += dPort
    data += tcpseq
    data += tcpackn
    data += tcpdorfws
    data += tcpcs
    data += tcpup
    data += bytes(tcppayload, 'utf-8')

    res=split_header2byteshex(data.hex())		
    tcpcs=ip_checksum(res,len(res)).to_bytes(2,'big')

    data=bytes(tcppayload, 'utf-8')

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    ip_header  = ipvitle 			# Version, IHL, Type of Service | Total Length
    ip_header += ipidffo 			# Identification | Flags, Fragment Offset
    ip_header += ipttlpt + ipcs  		# TTL, Protocol | Header Checksum
    ip_header += sIP  			# Source Address
    ip_header += dIP  			# Destination Address

    tcp_header  = sPort + dPort 		# Source Port | Destination Port
    tcp_header += tcpseq 			# Sequence Number
    tcp_header += tcpackn 			# Acknowledgement Number
    tcp_header += tcpdorfws 		# Data Offset, Reserved, Flags | Window Size
    tcp_header += tcpcs + tcpup 		# Checksum | Urgent Pointer

    packet = ip_header + tcp_header + data
    s.sendto(packet, (args.dIP, 0))
    print("Sending: " +packet.hex())
    s.close()

    # receive response of the handshake
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    while True:
      packet = s.recvfrom(65565)
      #packet string from tuple
      packet = packet[0]
      #take first 20 characters for the ip header
      ip_header = packet[0:20]
      #now unpack them :)
      iph = unpack('!BBHHHBBH4s4s' , ip_header)

      if bytes(map(int, socket.inet_ntoa(iph[8]).split('.')))==dIP:	
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);

        tcp_header = packet[iph_length:iph_length+20]
	
        #now unpack them :)
        tcph = unpack('!HHLLBBHHH' , tcp_header)
	
        source_port = tcph[0]
        dest_port = tcph[1]
        sequence = tcph[2]
        acknowledgement = tcph[3]
        doff_reserved = tcph[4]
        tcph_length = doff_reserved >> 4
	
  
        h_size = iph_length + tcph_length * 4
        data_size = len(packet) - h_size
        #get data from the packet
        data = packet[h_size:]
        print("\nResponse :"+str(data))

