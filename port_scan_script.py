import socket 
import sys
import time
from re import compile
from ipaddress import ip_address as addr
import ipaddress
'''
#Make a socket connection (TCP) with the specified port on the desired host
def scan_port(host, port):
	#Init TCP Socket
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		#Make connection to remote host, throw error if unsuccessful
		res_code = s.connect_ex((host, port))
	except:
		res_code = -1
	finally:
		# close the socket and return the result code to the caller. 0 means success.
		s.close()
		return res_code

#Get IP address to scan
#host = input("Input Host IP to Scan")
host = "192.168.207.41"
num_of_ports = 100
#Verify the input is a valid IP address
if addr(host):
	print("Scanning %s, Standby..." % host)

	#Begin port scan
	closed_port_count = 0
	for port in range (0, num_of_ports):
		res_code = scan_port(host,port)
		if res_code is 0:
			print("---Port %s is OPEN" % port)
		else:
			closed_port_count += 1
	#Print out summary of port scan
	print("%s of %s ports CLOSED" % (closed_port_count, num_of_ports))
	print("Scan complete")

else:
	print("Invalid Host")

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
'''
#Make a socket connection (TCP) with the specified port on the desired host
def scan_port(host, port):
	#Init TCP Socket
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		#Make connection to remote host, throw error if unsuccessful
		res_code = s.connect_ex((host, port))
	except:
		res_code = -1
	finally:
		# close the socket and return the result code to the caller. 0 means success.
		s.close()
		return res_code

#Takes user input and builds list of hosts to scan. This function returns a list of IPs
def build_hosts_list(host_list):
	ip_pattern = compile(r'\b(?:\.?(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){4}\b')
	total_hosts_to_scan = 0
	valid_host_list = []
	invalid_host_list = []
	# loops through each host, host range, cidr block and validates that it is in BYU domain
	for host in host_list:
	    host = host.lower().strip()
	    # range of IPs (X.X.X.X - Y.Y.Y.Y)
	    if "-" in host and ip_pattern.search(host):
	        # get start and end range values
	        hosts = host.split("-")
	        range_start = addr(hosts[0].strip())
	        range_end = addr(hosts[1].strip())
	        # verify that range is initially valid
	        if range_start < range_end:
	            total_hosts_to_scan += abs(int(range_start) - int(range_end))
	            start_ip = ipaddress.IPv4Address(range_start)
	            end_ip = ipaddress.IPv4Address(range_end)
	            for ip_int in range(int(start_ip), int(end_ip)):
	            	valid_host_list.append(ipaddress.IPv4Address(ip_int))
	        else:
	            print("ERROR - Invalid ip range syntax - " + host)
	            invalid_host_list.append(host)
	    # CIDR range (X.X.X.X/Y)
	    elif "/" in host:
	        hosts = host.split("/")
	        ip_base = addr(hosts[0])
	        cidr_suffix = int(hosts[1])
	        if 16 <= cidr_suffix <= 32:
	            # Calculate the number of hosts in a given CIDR range and add it to the total number of hosts to be scanned
	            total_hosts_to_scan += 2 ** (32 - cidr_suffix)
	            for ip in ipaddress.IPv4Network('192.168.1.0/24'):
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
	print("Total Number of Hosts To Scan: %s" % total_hosts_to_scan)
	# throw an error and output each of the host/host ranges that are not in BYU domain
	if invalid_host_list:
	    print("===List of Invalid Hosts Found===")
	    for host in invalid_host_list:
	        print(host)
	    print("===Fix Invalid Entries and Rerun==")
	    sys.exit(1)
	return valid_host_list

def get_ports_to_scan(specified_ports):
	ports = {'ports':[], 'start_port': None, 'end_port': None}

	if "-" in ports:
		ports = specified_ports.split("-")
		ports['start_port'] = int(ports[0].strip())
		ports['end_port'] = int(ports[1].strip())
	elif "," in ports:
		specified_ports = specified_ports.split(",")
		for port in specified_ports:
			ports['ports'].append(int(port.strip()))
	else:
		ports['ports'].append(specified_ports)

	return ports
#Get IP address to scan
#host = input("Input Host IP to Scan")
#TODO: Conver this to command line args
host = ["192.168.207.0/24"]
specified_ports = []
ports = get_ports_to_scan(specified_ports)

num_of_ports = 100

hosts = build_hosts_list(host)
print("Starting Scan for %s. Standby." % host)
for host in hosts:
	print("Scanning %s" % host)
	port = 22
	closed_port_count = 0
	res_code = scan_port(str(host),port)
	if res_code is 0:
		print("---Port %s is OPEN" % port)
	else:
		closed_port_count += 1

	'''#Begin port scan
	closed_port_count = 0
	for port in range (0, num_of_ports):
		res_code = scan_port(host,port)
		if res_code is 0:
			print("---Port %s is OPEN" % port)
		else:
			closed_port_count += 1
	#Print out summary of port scan
	print("%s of %s ports CLOSED" % (closed_port_count, num_of_ports))
	'''
print("Scan complete")


'''
Sources:
https://stackoverflow.com/questions/13368659/how-can-i-loop-through-an-ip-address-range-in-python
https://docs.python.org/3/library/socket.html

'''