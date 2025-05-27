#!/usr/bin/env python3

import logging
from scapy.all import sniff, IP, TCP

# Set up logging
logging.basicConfig(filename='intrusion.log', level=logging.INFO, 
                    format='%(asctime)s %(message)s')

# SYN flood detection
syn_count = {}
THRESHOLD = 5

def packet_callback(pkt):
    if IP in pkt and TCP in pkt:
        src = pkt[IP].src
        dport = pkt[TCP].dport
        flags = pkt[TCP].flags
        # SYN packet
        if flags == 0x02:
            syn_count[src] = syn_count.get(src, 0) + 1
            if syn_count[src] > THRESHOLD:
                logging.info(f"Suspicious SYN flood: {syn_count[src]} SYNs from {src}")
            else:
                logging.info(f"SYN packet from {src} to port {dport}")
    # Malformed packet detection (simple)
    elif IP in pkt and TCP not in pkt:
        logging.info(f"Malformed packet detected from {pkt[IP].src}")

def main():
    print("Starting packet sniffer... Press CTRL+C to stop.")
    sniff(filter='ip', prn=packet_callback, store=False)

if __name__ == '__main__':
    main()
