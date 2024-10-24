from scapy.all import *
from threading import Timer
import os

def udp_sniff(packet):
  # Check if packet has UDP layer and is DNS request
  if packet.haslayer(DNS) : 
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[UDP].sport
    dst_port = packet[UDP].dport

    # Extract hostname from DNS layer
    try:
      hostname = packet[DNS].qd.qname.decode('utf-8')
    except UnicodeDecodeError:
      hostname = "(Decoding failed: unknown encoding)"

  
    print(f" source IP: {src_ip}")
    print(f" destination IP: {dst_ip}")
    print(f" source port: {src_port}")
    print(f" destination port: {dst_port}")
    print(f" Hostname: {hostname}")
    if (hostname.startswith("www") and not(hostname.endswith('tr'))) or hostname.startswith("es") or hostname.startswith("wiki"):
            hostname = "https://" + hostname
            if hostname.endswith('.'):
                hostname = hostname[:-1]
            with open("urls.txt", "a") as file:
            	file.write(hostname + '\n')

  else:
    # Optional: Print a message for non-DNS packets
    pass


def main():
    """Main function to iterate through a list of URLs and capture screenshots."""

     # Capture UDP traffic on interface 'enp0s3' (filter for DNS requests)
    def capture_and_stop():
        sniff(iface='enp0s3', filter="udp dst port 53", prn=udp_sniff, timeout=12)  # Set timeout to 10 seconds

    # Start sniffing in a separate thread
    timer = Timer(0, capture_and_stop)  # Start after 0 seconds (immediately)
    timer.start()
    

if __name__ == "__main__":
    main()

