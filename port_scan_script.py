#!/bin/python
'''
	Created by Austin Baker
	October 2, 2018
'''
import socket 
import sys
import time
from re import compile
from ipaddress import ip_address as addr
import ipaddress
from reportlab.pdfgen import canvas
from copy import deepcopy

#Select tcp or udp scan based on user input
def scan_port(host, port, protocol,speed):
	if protocol == 'tcp':
		return scan_port_tcp(host,port,speed)
	elif protocol == 'udp':
		return scan_port_udp(host,port,speed)
	else:
		print("Error: Unsupported or missing Protocol ")
		raise ValueError 

#Make a socket connection (TCP) with the specified port on the desired host
def scan_port_tcp(host, port, speed):
	#Init TCP Socket
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	if(speed == 'T1'):
		s.settimeout(500)
	elif(speed == 'T2'):
		s.settimeout(2000)
	else:
		s.settimeout(5000)
	try:
		#Make connection to remote host, throw error if unsuccessful
		res_code = s.connect((host, port))
		s.close()
		return True
	except:
		return False

#Make a socket connection using UDP
def scan_port_udp(host,port,speed):
	s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	if(speed == 'T1'):
		s.settimeout(500)
	elif(speed == 'T2'):
		s.settimeout(2000)
	else:
		s.settimeout(5000)
	try:
		res_code = s.connect((host,port))
		return True
	except:
		return False

#Takes user input and builds list of hosts to scan. This function returns a list of IPs
def build_hosts_list(host):
	ip_pattern = compile(r'\b(?:\.?(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){4}\b')
	total_hosts_to_scan = 0
	valid_host_list = []
	invalid_host_list = []
	host = host.lower().strip()

	# range of IPs (X.X.X.X - Y.Y.Y.Y)
	if "-" in host and ip_pattern.search(host):
	    # get start and end range values
	    hosts = host.split("-")
	    range_start = addr(hosts[0].strip())
	    range_end = addr(hosts[1].strip())
	    # verify that range is initially valid
	    if range_start < range_end:
	        total_hosts_to_scan += abs(int(range_start) - int(range_end))+1
	        start_ip = ipaddress.IPv4Address(range_start)
	        end_ip = ipaddress.IPv4Address(range_end)
	        for ip_int in range(int(start_ip), int(end_ip)+1):
	        	valid_host_list.append(ipaddress.IPv4Address(ip_int))
	    else:
	        print("ERROR - Invalid ip range syntax - " + host)
	        invalid_host_list.append(host)
	# CIDR range (X.X.X.X/Y)
	elif "/" in host:
	    hosts = host.split("/")
	    ip_base = addr(hosts[0])
	    cidr_suffix = int(hosts[1])
	    # Don't allow scan to be performed on large subnets.
	    if 16 <= cidr_suffix <= 32:
	        # Calculate the number of hosts in a given CIDR range and add it to the total number of hosts to be scanned
	        total_hosts_to_scan += 2 ** (32 - cidr_suffix)
	        for ip in ipaddress.IPv4Network(host):
	        	valid_host_list.append(ip)
	    else:
	        print("ERROR - Invalid CIDR suffix or CIDR suffix is less than 16 - " + host)
	        invalid_host_list.append(host)
	# single IP
	else:
	    try:
	        host_ip = addr(host)  # Throws ValueError if host is not an IP address
	        total_hosts_to_scan += 1
	        valid_host_list.append(host)
	    # non-IP
	    except ValueError:
	        print("ERROR - Not a valid IP - " + host)
	        invalid_host_list.append(host)
	# throw an error and output each of the host/host ranges that are not valid
	if invalid_host_list:
	    for host in invalid_host_list:
	        print("   Verify Input: " + host)
	    sys.exit(1)
	print("Total Number of Hosts To Scan: %s" % total_hosts_to_scan)
	return valid_host_list

# builds list of ports from passed in user input.
def get_ports_to_scan(specified_ports):
	ports = {'ports':[], 'start_port': None, 'end_port': None}
	# Handle range
	if "-" in specified_ports:
		specified_ports = specified_ports.split("-")
		ports['start_port'] = int(specified_ports[0].strip())
		ports['end_port'] = int(specified_ports[1].strip())
	# Handle list
	elif "," in specified_ports:
		specified_ports = specified_ports.split(",")
		for port in specified_ports:
			ports['ports'].append(int(port.strip()))
	# Handle single port
	else:
		ports['ports'].append(int(specified_ports))

	return ports

#Prints out open ports to the console
def print_port_state(res_code, port,to_pdf):
	if res_code == True:
		to_print = "---Port %s is OPEN" % port
		print(to_print)
		to_pdf.append(deepcopy(to_print))

#Print scan results to pdf
def print_to_pdf(to_pdf):
	c = canvas.Canvas("scan_results.pdf")
	start = 765
	for line in to_pdf:
		start -=15
		c.drawString(100,(start),line)
	c.save()


# Get user input from the command line. Show usage if they syntax is incorrect
try:
	protocol = sys.argv[1]
	host = sys.argv[2]
	specified_ports = sys.argv[3]
	speed = sys.argv[4]
	try:
		make_file = sys.argv[5]
		if make_file == 'oF-yes':
			make_file = True
		else:
			make_file = False
	except:
		make_file = False
except:
	print("Usage: port_scan_script.py <protocol> <host> <ports> <speed> <oF-yes")
	sys.exit(1)

# build ports and hosts object using user supplied input
ports = get_ports_to_scan(specified_ports)
#print(ports)
to_pdf = []
to_pdf.append("Port Scan Results:")
hosts = build_hosts_list(host)

print("Starting Scan for %s. Standby." % host)
try:
	# Scan each host with specified ports
	for host in hosts:
		print("Scanning %s" % host)
		to_pdf.append(deepcopy(str(host)))
		closed_port_count = 0
		if ports['start_port'] != None and ports['end_port'] != None:
			for port in range(ports['start_port'], ports['end_port']+1):
				res_code = scan_port(str(host),port,protocol,speed)
				print_port_state(res_code,port,to_pdf)
		elif len(ports['ports']) > 1:
			for port in ports['ports']:
				res_code = scan_port(str(host),port,protocol,speed)
				print_port_state(res_code,port,to_pdf)
		else:
			for port in ports['ports']:
				res_code = scan_port(str(host),port,protocol,speed)
				print_port_state(res_code,port,to_pdf)
	print("Scan complete")
	if make_file:
		print_to_pdf(to_pdf)
except KeyboardInterrupt:
	print("Exiting the Scan.")
	sys.exit(1)


'''
Sources:
https://stackoverflow.com/questions/13368659/how-can-i-loop-through-an-ip-address-range-in-python
https://docs.python.org/3/library/socket.html

'''