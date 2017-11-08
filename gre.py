#!/usr/bin/python

import socket
import sys
from struct import *

# checksum functions needed for calculation checksum
def checksum(msg):
    s = 0
     
    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
        s = s + w
     
    s = (s>>16) + (s & 0xffff);
    s = s + (s >> 16);
     
    #complement and mask to 4 byte short
    s = ~s & 0xffff
     
    return s


try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

except socket.error, msg:
    print "Socket error:"+str(msg[0])
    sys.exit()

packet = ''

# top  header
source_ip = '100.100.100.1'
dest_ip = '100.100.100.2'

ip_ihl = 5
ip_ver = 4
ip_tos = 0
ip_tot_len = 0
ip_id = 54321
ip_frag_off = 0
ip_ttl = 255
ip_proto = 4    # IPIP(4)
ip_check= 0
ip_saddr = socket.inet_aton(source_ip)
ip_daddr = socket.inet_aton(dest_ip)
ip_ihl_ver = (ip_ver <<4 )+ip_ihl

ip_header = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

#Inner header
inner_source_ip='200.200.200.1'
inner_dest_ip='200.200.200.2'

gre_ip_ihl = 5
gre_ip_ver = 4
gre_ip_tos = 0
gre_ip_tot_len = 76
gre_ip_id = 54320
gre_ip_frag_off = 0
gre_ip_ttl = 255
gre_ip_proto = socket.IPPROTO_UDP
gre_ip_check= 0
gre_ip_saddr = socket.inet_aton(inner_source_ip)
gre_ip_daddr = socket.inet_aton(inner_dest_ip)
gre_ip_ihl_ver = (ip_ver <<4 )+ip_ihl




#UDP header
udp_source = 1812
udp_dest = 1812
udp_check = 0
udp_len = 0

udp_header = pack('!HHHH', udp_source, udp_dest, udp_len, udp_check)

#RADIUS CoA Request
rad_code = 43
rad_id = 180
rad_auth = chr(0)
rad_len = 0
#RADIUS attributes
attr_type = 1
attr_len = 0
attr_value = '00:54:2e:aa:47:90'
#RADIUS Attributes Vendor ID
vendor_type = 26
vendor_len = 0
vendor_id = 2352

vendor_attr_type = 105
vendor_attr_len = 0
vendor_attr_value = ""


rad_header = pack('!BBH16sBB17sBBIBBs',rad_code, rad_id, rad_len, rad_auth, attr_type, attr_len, attr_value,vendor_type, vendor_len, vendor_id, vendor_attr_type, vendor_attr_len, vendor_attr_value )

vendor_attr_len = 2+len(vendor_attr_value)
vendor_len = vendor_attr_len+6
attr_len = len(attr_value)+2
rad_len = vendor_len+attr_len+20

rad_header = pack('!BBH16sBB17sBBIBBs',rad_code, rad_id, rad_len, rad_auth, attr_type, attr_len, attr_value,vendor_type, vendor_len, vendor_id, vendor_attr_type, vendor_attr_len, vendor_attr_value )


# source_address = socket.inet_aton(source_ip)
# dest_address = socket.inet_aton(dest_ip)
source_address = socket.inet_aton(inner_source_ip)
dest_address = socket.inet_aton(inner_dest_ip)

placeholder = 0
# protocol = socket.IPPROTO_UDP
udp_len = len(udp_header) + len(rad_header) 
print (udp_len)

psh = pack('!4s4sBBH', source_address, dest_address, placeholder, gre_ip_proto, (udp_len*2))
psh = psh + udp_header + rad_header

udp_check = checksum(psh)
# udp_check = 0x2e3b
gre_ip_tot_len = 20 + udp_len
gre_ip_header = pack('!BBHHHBBH4s4s', gre_ip_ihl_ver, gre_ip_tos, gre_ip_tot_len, gre_ip_id, gre_ip_frag_off, gre_ip_ttl, gre_ip_proto, gre_ip_check, gre_ip_saddr, gre_ip_daddr)
gre_ip_check = checksum(gre_ip_header)
gre_ip_header = pack('!BBHHHBB', gre_ip_ihl_ver, gre_ip_tos, gre_ip_tot_len, gre_ip_id, gre_ip_frag_off, gre_ip_ttl, gre_ip_proto) + pack('H',gre_ip_check) +pack('!4s4s',gre_ip_saddr, gre_ip_daddr)


udp_header = pack('!HH', udp_source, udp_dest) + pack('!H', udp_len) + pack('H', udp_check)
packet = ip_header + gre_ip_header + udp_header + rad_header
s.sendto(packet, (dest_ip, 0))

