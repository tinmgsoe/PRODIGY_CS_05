import socket
from scapy.all import *

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        print(f"Source IP: {src_ip} --> Destination IP: {dst_ip} Protocol: {protocol}")

        if TCP in packet:
            print("TCP Segment:")
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"Source Port: {src_port} --> Destination Port: {dst_port}")
            print(f"Payload: {str(packet[TCP].payload)}")

        elif UDP in packet:
            print("UDP Datagram:")
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"Source Port: {src_port} --> Destination Port: {dst_port}")
            print(f"Payload: {str(packet[UDP].payload)}")

def start_sniffer(interface):
    print(f"Sniffing on interface {interface}...")
    sniff(iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    # Replace "eth0" with the name of your network interface
    start_sniffer("Wi-Fi")
