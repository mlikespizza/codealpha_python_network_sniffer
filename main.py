import sys
from scapy.all import *

from scapy.layers.inet import IP, TCP

#function for handling packets
#parameters of the function are 'packet' for the packets flowing, and 'log' for the log file to store logs
def handle_packet(packet, logfile):
    if packet.haslayer(TCP):
        #storing source,destination IP and port into the variable called packet
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        if packet.haslayer(Raw):
            payload = packet[Raw].load
        else:
            payload = None

        #logfile is a file that will store write to it basically
        logfile.write(f"TCP Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port} Payload:{payload}\n")

#main function with the parameters; 'interface', and 'verbose', which is off by default
def main(interface, verbose=False):
    #naming the logfile
    logfile_name = f"sniffer_{interface}_log.txt"
    #opens the logfile and enables me to write
    with open(logfile_name, 'w') as logfile:
        try:
            if verbose:
                # calling handle_packet function i created earlier, and passing it in the pkt and logfile
                # iface is the interface
                sniff(iface=interface, prn=lambda pkt: handle_packet(pkt, logfile), store=0, verbose=verbose)
            else:
                sniff(iface=interface, prn=lambda pkt: handle_packet(pkt, logfile), store=0)
        #this means that it will keep running unless i clicked "ctrl + c" on the terminal
        except KeyboardInterrupt:
            sys.exit(0)

if __name__ == "__main__":
    # there has to be either 2 or 3 arguments
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python sniffer.py <interface> [verbose]")
        sys.exit(1)
    verbose = False
    if len(sys.argv) == 3 and sys.argv[2].lower() == "verbose":
        verbose = True
    main(sys.argv[1], verbose)