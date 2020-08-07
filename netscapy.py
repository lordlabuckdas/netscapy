#!/usr/bin/env python
from scapy.all import *
import argparse
from random import randint


SUBNET_IP = get_if_addr(conf.iface).split('.')[:-1]
GATEWAY_IP = '.'.join(SUBNET_IP+['1'])
GATEWAY_MAC = getmacbyip(GATEWAY_IP)

def arp_scan():
	# arp scan to get all hosts online
	print('\n[*] Starting ARP scan...')
	ip_list = []
	print('[*] IPs found:')
	# broadcast address is ff:ff:ff:ff:ff:ff
	pkt = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=GATEWAY_IP + '/24')
	res = srp(pkt, timeout = 0.2, verbose = False)[0]
	for x in res:
		print('[+] ' + x[1].psrc)
		ip_list.append(x[1].psrc)

	return ip_list


def port_scan(ip_list, ports, ttl):
	# iterate through ips and ports
	print('\n[*] Starting port scan...\n[*] Open Ports:')
	for ip in ip_list:
		for port in ports:
			try:
				# send SYN packet 
				pkt = IP(dst=str(ip), ttl=ttl)/TCP(dport=int(port), flags='S')
				# verbose to 0 for reducing clutter in stdout
				# timeout to 0.2 so that it doesn't wait too long for SYN-ACK
				syn_resp = sr1(pkt, timeout=0.2, verbose=0)
				
				# checking for SYNC-ACK
				if syn_resp[TCP].flags == 'SA':
					print('[+] ' + ip + ' : '+ str(port))

				# send RST signal so that port is back for normal use quicker
				sr(IP(dst=str(ip), ttl=ttl)/TCP(dport=int(port), flags='R'), verbose=0, timeout=0.2)
			except:
				pass # to handle no response from ports
	print()


def main():
	# command line argument parser
	ap = argparse.ArgumentParser(description = 'port scanner using scapy')
	
	ap.add_argument('--addr', '-a', help='ipv4 addresses / ipv6 addresses / domain name (comma separated)', metavar='ADDRESSES', default='0')
	ap.add_argument('--prts', '-p', help='ports to scan (comma separated)\nscans most common ports by default', default='0', metavar='PORTS')
	ap.add_argument('--ttl', '-t', help='spoof ttl - enter value or leave empty for random', default=randint(1,128), metavar='TTL')
	ap.add_argument('--full', '-f', help='full network scan - all ips and ports in subnet', action='store_true')
	
	args = ap.parse_args()
	
	# sets ttl, either random or from user
	ttl = args.ttl 

	if args.prts == '0':
		ports = [20, 21, 22, 23, 25, 80, 110, 443] # common ports
	else:
		ports = args.prts.split(',') # user ports

	if args.full and args.addr != '0':
		print('\n[-] Use either, not both\n')
		return
	elif args.full == False and args.addr == '0':
		print('\n[-] Enter address or use -f for full network scan\n')
		return

	if args.full:
		ip_list = arp_scan() # scan entire /24 subnet

	if args.addr != '0':
		ip_list = args.addr.split(',')

	port_scan(ip_list, ports, ttl=ttl)



if __name__ == '__main__':
	main()
