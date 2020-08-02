from scapy.all import *
import argparse
from random import randint

ports = { 'FTP': 20,'FTP': 21, 'SSH': 22, 'Telnet': 23, 'SMTP': 25, 'HTTP': 80, 'POP3': 110, 'HTTPS': 443 }

def arp_scan():
	pkt = Ether(dst = 'ff:ff:ff:ff:ff:ff')/ARP(pdst = get_if_addr(conf.iface) + '/24')
	res = srp(pkt, timeout = 2, verbose = False)[0]
	for x in res:
		print(x[1].psrc)

def main():
	# ap = argparse.ArgumentParser(description = 'port scanner using scapy')
	# ap.add_argument('--addr', '-a', help='ipv4 addresses / ipv6 addresses / domain name (comma separated)', type=str, action='store_true')
	# ap.add_argument('--port', '-p', help='ports to scan (comma separated)\nscans most common ports by default', type=str)
	# ap.add_argument('--ttl', '-t', help='random value by default', action='store_true')
	# ap.add_argument('--src', '-s', help='fake source address', action='store_true')
	# args = ap.parse_args()
	# addr = addr_resolve(args.addr)
	arp_scan()


if __name__ == '__main__':
	main()
