from scapy.all import *
import argparse
from random import randint

PORTS_DICT = { 'FTP': 20,'FTP': 21, 'SSH': 22, 'Telnet': 23, 'SMTP': 25, 'HTTP': 80, 'POP3': 110, 'HTTPS': 443 }

RAND_IP = str(randint(1,255)) + '.' + str(randint(1,255)) + '.' + str(randint(1,255)) + '.' + str(randint(1,255))

def arp_scan():
	pkt = Ether(dst = 'ff:ff:ff:ff:ff:ff')/ARP(pdst = get_if_addr(conf.iface) + '/24')
	res = srp(pkt, timeout = 2, verbose = False)[0]
	print('\n[*] IPs found:')
	ip_list = []
	for x in res:
		print('[+] ' + x[1].psrc)
		ip_list += x[1].psrc
	else:
		print()
	return ip_list

def addr_resolve(addrs):
	# some regex magic to get ipv4
	ip_list = []
	#for addr in addrs:	
	return ip_list
	

def main():
	ap = argparse.ArgumentParser(description = 'port scanner using scapy')
	
	ap.add_argument('--addr', '-a', help='ipv4 addresses / ipv6 addresses / domain name (comma separated)', metavar='ADDRESSES', default='0')
	ap.add_argument('--prts', '-p', help='ports to scan (comma separated)\nscans most common ports by default', default='0', metavar='PORTS')
	ap.add_argument('--ttl', '-t', help='spoof ttl - enter value or leave empty for random', default=randint(1,128), metavar='TTL')
	ap.add_argument('--src', '-s', help='spoof address - enter value or leave empty for random', default=RAND_IP, metavar='SOURCE_IP')
	ap.add_argument('--full', '-f', help='full scan - all ips and ports in subnet', action='store_true')
	
	args = ap.parse_args()
	
	ttl = args.ttl 

	src = args.src

	if args.prts == '0':
		ports = [20, 21, 22, 23, 25, 80, 110, 443]
	else:
		ports = args.prts.split(',')

	if args.full and args.addr != '0':
		print('\n[-] Use either, not both\n')
		return

	if args.full:
		ip_list = arp_scan()

	if args.addr != '0':
		ip_list = addr_resolve(args.addr.split(','))




if __name__ == '__main__':
	main()
