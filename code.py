from scapy.all import sniff

# Define a packet callback function
def packet_callback(packet):
    print(packet.show())

# Start sniffing (you can change 'en0' to your network interface)
sniff(prn=packet_callback, iface='en0', count=10)
