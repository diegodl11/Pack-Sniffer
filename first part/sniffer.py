import socket
import struct
import textwrap

# Tab spaces for indentation
TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

# Capturing traffic
def main():
    """
    Main function of the program.
    """

    # Create a socket to capture Ethernet frames
    conn=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))

  


    # Continuously capture Ethernet frames
    while True:

        
        # Receive raw data and address
        raw_data, addr = conn.recvfrom(65535)

        # Unpack the Ethernet frame into its components
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        # Print Ethernet frame information
        print(TAB_1 + 'Destination : {}, Source : {}, Protocol : {}'.format(dest_mac, src_mac, eth_proto))

        # Check if the protocol is IPv4 (8)
        if eth_proto == 8:
            # Unpack IPv4 packet headers
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print(TAB_1 + 'IPv4 Packet : ')
            print(TAB_2 + 'Version : {}, Header Length : {}, TTL : {}'.format(version, header_length, ttl))
            print(TAB_2 + 'Protocol : {}, Source : {}, Target : {}'.format(proto, src, target))

            # Check the protocol within IPv4 packet
            if proto == 1:  # ICMP
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type :{}, Code :{}, CheckSum :{}'.format(icmp_type, code, checksum))
                print(TAB_2 + 'Data : ')
                print(format_multi_line(DATA_TAB_3, data))

            elif proto == 6:  # TCP
                (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn,
                 flag_fin, data) = tcp_segment(data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port:{}, Destination Port:{}'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence:{}, Acknowledgement:{}'.format(sequence, acknowledgement))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG:{}, ACK:{}, PSH:{}, RST:{}, SYN:{}, FIN:{}'.format(flag_urg, flag_ack, flag_psh,
                                                                                        flag_rst, flag_syn, flag_fin))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))

            elif proto == 17:  # UDP
                src_port, dest_port, length, data = udp_segment(data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port:{}, Destination Port:{}, Length:{}'.format(src_port, dest_port, length))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))

            else:
                # Other IPv4 data
                print(TAB_1 + 'Other IPv4 Data:')
                print(format_multi_line(DATA_TAB_2, data))
        else:
            # Ethernet data
            print('Ethernet Data:')
            print(format_multi_line(DATA_TAB_1, data))


# Unpack Ethernet frame
def ethernet_frame(data):
    """
    Function to unpack an Ethernet frame.

    Args:
        data (bytes): Ethernet frame data.

    Returns:
        tuple: Tuple with Ethernet frame information.
    """
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])

    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


# Return properly formatted MAC address
def get_mac_addr(byte_addr):
    """
    Function to format a MAC address.

    Args:
        byte_addr (bytes): MAC address in bytes.

    Returns:
        str: Formatted MAC address.
    """
    bytes_str = []
    for char in byte_addr:
         bytes_str.append('{:02x}'.format(ord(char)))
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr


# Unpack IP Packet headers

# Unpacks IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
	
    #we translate to binary from hex
    version_header_length = bin(int(version_header_length, 16))[2:]
  
    #we translate to int to use the operator >>
    version = int(version_header_length) >> 4
    
    header_length = (int(version_header_length) & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


def ipv4(addr):
    return '.'.join(map(str, addr))


# Unpacks ICMP Packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


# Unpacks TCP segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H',
                                                                                            data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = (offset_reserved_flags & 1)

    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, \
           data[offset:]


# Unpacks UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


# Formats multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        new_string = []
	for byte in string:
	  new_string.append(r'\x{:02x}'.format(ord(byte)))
	string = ''.join(new_string)
        if size % 2:
            size -= 1

    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


main()
