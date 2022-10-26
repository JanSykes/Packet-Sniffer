#G20831731

import socket
import struct
import textwrap
import binascii
import struct
import sys


def main():
    conn = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    filters = (["ICMP", 1, "ICMP"],["UDP", 17, "UDP"], ["TCP", 6, "TCP"])
    filter = []

    if len(sys.argv) == 2:
        print("Filter: ", sys.argv[1])
        for i in filters:
            if sys .argv[1] == i[0]:
                filter = i



    while True:
        raw_data, addr = conn.recvfrom(65536)
        destination_mac, source_mac, eth_proto, data = ethernet_frame(raw_data)

        if eth_proto == 'IP':
            packetNew, protoNext = ipheader(data, filter)
            printPackets(filter, protoNext, packetNew)

        elif eth_proto == 'IPV4':
            printPacketsV4(filter, data, raw_data)



def printPacketsV4(filter, data, raw_data):
    (version, header_length, ttl, proto, source, target, data) = ipv4_Packet(data)

    #ICMP Packets
    if proto == 1 and (len(filter) == 0 or filter[1] == 1):
        icmp_type, code, checksum, data = icmp_packet(data)
        print ("ICMP")
        print ("\tICMP type: %s" % (icmp_type))
        print ("\tICMP code: %s" % (code))
        print ("\tICMP checksum: %s" % (checksum))

    #TCP Packets
    elif proto == 6 and (len(filter) == 0 or filter[1] == 6):
        print("TCP")
        print('Version: {}\nHeader Length: {}\nTTL: {}'.format(version, header_length, ttl))
        print('protocol: {}\nSource: {}\nTarget: {}'.format(proto, source, target))
        source_port, destination_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh = struct.unpack(
            '! H H L L H H H H H H', raw_data[:24])
        print('TCP Segment')
        print('Source Port: {}\nDestination Port: {}'.format(source_port, destination_port))
        

        if len(data) > 0:
            # HTTP Packets
            if source_port == 80 or destination_port == 80:
                print('HTTP Data')
                try:
                    http = HTTP(data)
                    http_info = str(http.data).split('\n')
                    for line in http_info:
                        print(str(line))
                except:
                    print(format_output_line("",data))
            else:
                print('TCP Data')
                print(format_output_line("",data))
    # UDP Packets
    elif proto == 17 and (len(filter) == 0 or filter[1] == 17):
        print("UDP")
        print('Version: {}\nHeader Length: {}\nTTL: {}'.format(version, header_length, ttl))
        print('protocol: {}\nSource: {}\nTarget: {}'.format(proto, source, target))
        source_port, destination_port, length, data = udp_seg(data)
        print('UDP Segment')
        print('Source Port: {}\nDestination Port: {}\nLength: {}'.format(source_port, destination_port, length))


def printPackets(filter, protoNext, packetNew):
    remainingPacket = ""

    if (protoNext == 'ICMP' and (len(filter) == 0 or filter[2] == "ICMP")):
        remainingPacket = icmpHeader(packetNew)
    elif (protoNext == 'TCP' and (len(filter) == 0 or filter[2] == "TCP")):
        remainingPacket = tcpHeader(packetNew)
    elif (protoNext == 'UDP' and (len(filter) == 0 or filter[2] == "UDP")):
        remainingPacket = udpHeader(packetNew)

    return remainingPacket


def tcpHeader(PacketNew):
    #unpacking the packets
    packet = struct.unpack("!2H2I4H", PacketNew[0:20])
    sorcePort = packet[0]
    dstinationPort = packet[1]
    sqncNum = packet[2]
    acknNum = packet[3]
    dataOffset = packet[4] >> 12
    reserved = (packet[4] >> 6) & 0x003F
    tcpFlags = packet[4] & 0x003F 
    urgFlag = tcpFlags & 0x0020 
    ackFlag = tcpFlags & 0x0010 
    pushFlag = tcpFlags & 0x0008 
    window = packet[5]
    checkSum = packet[6]
    urgPntr = packet[7]

    print ("TCP")
    print ("\tSource Port: "+str(sorcePort) )
    print ("\tDestination Port: "+str(dstinationPort) )
    print ("\tSequence Number: "+str(sqncNum) )
    print ("\tAck. Number: "+str(acknNum) )
    print ("\tData Offset: "+str(dataOffset) )
    print ("\tReserved: "+str(reserved) )
    print ("\tTCP Flags: "+str(tcpFlags) )

    if(urgFlag == 32):
        print ("\tUrgent Flag: Set")
    if(ackFlag == 16):
        print ("\tAck Flag: Set")
    if(pushFlag == 8):
        print ("\tPush Flag: Set")

    print ("\tWindow: "+str(window))
    print ("\tChecksum: "+str(checkSum))
    print ("\tUrgent Pointer: "+str(urgPntr))
    print (" ")

    packet = packet[20:]
    return packet


def udpHeader(PacketNew):
    packet = struct.unpack("!4H", PacketNew[0:8])
    surcePort = packet[0]
    dstinationPort = packet[1]
    lenght = packet[2]
    checkSum = packet[3]

    print ("UDP")
    print ("\tSource Port: "+str(surcePort))
    print ("\tDestination Port: "+str(dstinationPort))
    print ("\tLenght: "+str(lenght))
    print ("\tChecksum: "+str(checkSum))
    print (" ")

    packet = packet[8:]
    return packet


def icmpHeader(data):
    ip_icmp_type, ip_icmp_code, ip_icmp_chekcsum = struct.unpack(
        ">BBH", data[:4])

    print ("ICMP")
    print ("\tICMP type: %s" % (ip_icmp_type))
    print ("\tICMP code: %s" % (ip_icmp_code))
    print ("\tICMP checksum: %s" % (ip_icmp_chekcsum))

    data = data[4:]
    return data


def nextHeader(ip_next_header):
    if (ip_next_header == 6):
        ip_next_header = 'TCP'
    elif (ip_next_header == 17):
        ip_next_header = 'UDP'
    elif (ip_next_header == 43):
        ip_next_header = 'Routing'
    elif (ip_next_header == 1):
        ip_next_header = 'ICMP'
    elif (ip_next_header == 58):
        ip_next_header = 'ICMPv6'
    elif (ip_next_header == 44):
        ip_next_header = 'Fragment'
    elif (ip_next_header == 0):
        ip_next_header = 'HOPOPT'
    elif (ip_next_header == 60):
        ip_next_header = 'Destination'
    elif (ip_next_header == 51):
        ip_next_header = 'Authentication'
    elif (ip_next_header == 50):
        ip_next_header = 'Encapsuling'

    return ip_next_header


def ipheader(data, filter):
    ip_first_word, ip_payload_legth, ip_next_header, ip_hoplimit = struct.unpack(
        ">IHBB", data[0:8])
    ip_src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
    ip_dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])

    bin(ip_first_word)
    "{0:b}".format(ip_first_word)
    version = ip_first_word >> 28
    traffic_class = ip_first_word >> 16
    traffic_class = int(traffic_class) & 4095
    flow_label = int(ip_first_word) & 65535

    ip_next_header = nextHeader(ip_next_header)
    data = data[40:]

    return data, ip_next_header


# Unpacking the ethernet frame
def ethernet_frame(data):
    proto = ""
    Ipheader = struct.unpack("!6s6sH",data[0:14])
    dstmac = binascii.hexlify(Ipheader[0]) 
    srcmac = binascii.hexlify(Ipheader[1]) 
    protoType = Ipheader[2] 
    protoNext = hex(protoType) 

    if (protoNext == '0x800'): 
        proto = 'IPV4'
    elif (protoNext == '0x86dd'): 
        proto = 'IP'

    data = data[14:]

    return dstmac, srcmac, proto, data

    #MAC address fomratting
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

# Unpacking ipv4 packets
def ipv4_Packet(data):
    version_header_len = data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    ttl, proto, source, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_len, ttl, proto, ipv4(source), ipv4(target), data[header_len:]

#ip address formatting
def ipv4(addr):
    return '.'.join(map(str, addr))


# ICMP packets unpacking
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# TCP packets unpacking
def tcp_seg(data):
    (source_port, destination_port, sequence, acknowledgement, offset_reserved_flag) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flag >> 12) * 4
    flag_urg = (offset_reserved_flag & 32) >> 5
    flag_ack = (offset_reserved_flag & 32) >> 4
    flag_psh = (offset_reserved_flag & 32) >> 3
    

    return source_port, destination_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, data[offset:]


# Unpacking UDP packets
def udp_seg(data):
    source_port, destination_port, size = struct.unpack('! H H 2x H', data[:8])
    return source_port, destination_port, size, data[8:]

# Outline formatting
def format_output_line(prefix, string):
    size=80
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size-= 1
            return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

main()









#References
#1)Uv.mx. 2022. [online] Available at: <https://www.uv.mx/personal/angelperez/files/2018/
 # 10/sniffers_texto.pdf> [Accessed  28 November 2021].
 
#2)Bitforestinfo.com. 2022. Create Simple Packet Sniffer Using Python - Bitforestinfo. [online] Available at: 
# <https://www.bitforestinfo.com/blog/02/15/how-to-write-simple-packet-sniffer.html> [Accessed 18 December 2021].

#3)Tutorialspoint.com. 2022. Network Packet Sniffing. [online] Available at: 
# <https://www.tutorialspoint.com/python_penetration_testing/python_penetration_testing_network_packet_sniffing.htm> [Accessed 19 February 2022].

#4)Moon, S., 2022. Code a network Packet Sniffer in Python for Linux - BinaryTides. [online] BinaryTides. Available at: <https://www.binarytides.com/python-packet-sniffer-code-linux/> [Accessed 7 March 2022].

#5)Docs.python.org. 2022. 8. Errors and Exceptions — Python 3.10.4 documentation. [online] Available at: <https://docs.python.org/3/tutorial/errors.html> [Accessed 12 March 2022].

#6)Docs.python.org. 2022. socket — Low-level networking interface — Python 3.10.4 documentation. [online] Available at: <https://docs.python.org/3/library/socket.html> [Accessed 16 March 2022].