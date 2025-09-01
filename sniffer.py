from scapy.all import *

def packet_handler(packet):
    """
    This function processes each captured packet.
    """
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        # Extract the IP and TCP/UDP layers
        ip_layer = packet.getlayer(IP)
        
        # Determine the protocol and get the port information
        if packet.haslayer(TCP):
            proto = "TCP"
            src_port = packet.getlayer(TCP).sport
            dst_port = packet.getlayer(TCP).dport
        elif packet.haslayer(UDP):
            proto = "UDP"
            src_port = packet.getlayer(UDP).sport
            dst_port = packet.getlayer(UDP).dport
        elif packet.haslayer(ICMP):
            proto = "ICMP"
            src_port = "N/A"
            dst_port = "N/A"
        else:
            proto = "Other"
            src_port = "N/A"
            dst_port = "N/A"

        # Print the packet information
        print(f"Protocol: {proto} | Source IP: {ip_layer.src}:{src_port} -> Destination IP: {ip_layer.dst}:{dst_port}")

def start_sniffer():
    """
    Starts the packet sniffer on the default interface.
    """
    print("Starting network traffic analyzer...")
    print("Press Ctrl+C to stop.")
    
    # Use sniff() to capture packets and pass them to our handler function
    # 'prn' is the function to be called for each packet.
    sniff(prn=packet_handler, store=0)

if __name__ == "__main__":
    start_sniffer()