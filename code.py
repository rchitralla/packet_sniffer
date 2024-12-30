#!/usr/bin/env python3

import sys
from scapy.all import sniff

def packet_callback(packet):
    """
    This function will be called each time a packet is captured.
    """
    print(packet.show(dump=True))  # dump=True returns a string instead of printing directly

def main():
    """
    Start sniffing on the specified network interface.
    You can specify a count to limit the number of packets captured,
    or leave it out to capture indefinitely.
    """
    interface = 'en0'  # Replace with your network interface (e.g., 'eth0', 'wlan0' on Linux, etc.)
    packet_count = 10   # Number of packets to capture; set to 0 or None for unlimited

    # Start sniffing
    print(f"[*] Starting packet sniffing on interface: {interface}")
    sniff(prn=packet_callback, iface=interface, count=packet_count)
    print(f"[*] Stopped packet sniffing after capturing {packet_count} packets.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Packet sniffing interrupted by user.")
        sys.exit(0)

