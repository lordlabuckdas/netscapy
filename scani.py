from scapy.all import *
import argparse
from random import randint


RAND_IP = str(randint(1,255)) + '.' + str(randint(1,255)) + '.' + str(randint(1,255)) + '.' + str(randint(1,255))
GATEWAY_IP = '.'.join(get_if_addr(conf.iface).split('.')[:-1]+['1'])
GATEWAY_MAC = getmacbyip(GATEWAY_IP)

def arp_scan():
	print('\n[*] Starting ARP scan...')
	pkt = Ether(dst='ff:ff:ff:ff:ff:ff', src=GATEWAY_MAC)/ARP(psrc=GATEWAY_IP, pdst=get_if_addr(conf.iface) + '/24')
	res = srp(pkt, timeout = 0.2, verbose = False)[0]
	print('[*] IPs found:')
	ip_list = []
	for x in res:
		print('[+] ' + x[1].psrc)
		ip_list.append(x[1].psrc)
	else:
		print()
	return ip_list


def addr_resolve(addrs):
	# some regex magic to get ipv4
	ip_list = []
	#for addr in addrs:	
	return ip_list
	

def port_scan(ip_list, ports):
	# iterate through ips and ports
	print('[*] Starting port scan...\n[*] Open Ports:')
	for ip in ip_list:
		for port in ports:
			try:
				pkt = IP(dst=str(ip), src=GATEWAY_IP)/TCP(dport=int(port))
				syn_resp = sr1(pkt, timeout=0.2, verbose=0)
						
				if syn_resp[TCP].flags == 'SA':
					print('[+] ' + ip + ' : '+ str(port))

				sr1(IP(dst=str(ip), src=src)/TCP(dport=syn_resp.sport, flags='R'), verbose=0, timeout=0.2)
			except:
				pass
	print()


def main():
	ap = argparse.ArgumentParser(description = 'port scanner using scapy')
	
	ap.add_argument('--addr', '-a', help='ipv4 addresses / ipv6 addresses / domain name (comma separated)', metavar='ADDRESSES', default='0')
	ap.add_argument('--prts', '-p', help='ports to scan (comma separated)\nscans most common ports by default', default='0', metavar='PORTS')
	ap.add_argument('--ttl', '-t', help='spoof ttl - enter value or leave empty for random', default=randint(1,128), metavar='TTL')
	ap.add_argument('--full', '-f', help='full network scan - all ips and ports in subnet', action='store_true')
	
	args = ap.parse_args()
	
	ttl = args.ttl 

	if args.prts == '0':
		ports = [20, 21, 22, 23, 25, 80, 110, 443]
	else:
		ports = args.prts.split(',')

	if args.full and args.addr != '0':
		print('\n[-] Use either, not both\n')
		return
	elif args.full == False and args.addr == '0':
		print('\n[-] Enter address or use -f for full network scan\n')
		return

	if args.full:
		ip_list = arp_scan()

	if args.addr != '0':
		ip_list = addr_resolve(args.addr.split(','))

	port_scan(ip_list, ports)




if __name__ == '__main__':
	main()
