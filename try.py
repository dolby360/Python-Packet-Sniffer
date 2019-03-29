from scapy.all import ARP, sniff
 
def arp_display(pkt):
    if pkt[ARP].op == 1:  # who-has (request)
        print( "Request: " + str(pkt[ARP].psrc) + " is asking about " + str(pkt[ARP].pdst)) 
        
    if pkt[ARP].op == 2:  # is-at (response)
        print( "Response: " + str(pkt[ARP].hwsrc) + " has address " + str(pkt[ARP].psrc))
 
sniff(prn=arp_display, filter="arp")