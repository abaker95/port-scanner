Port Scanner Summary

To run this script make sure that python3 is installed. This script also requires the reportlab library. This can be installed via pip (pip install reportlab).

Command Usage:

python port_scan_script.py <protocol> <ip_address> <port> <speed> <print>

protocol: Protocol used for scan. Set using 'tcp' or 'udp'
ip_address: IP to be scanned. Can take single IP (x.x.x.x), IP range (x.x.x.x-y.y.y.y), or CIDR (x.x.x.x/y)
port: Port to be scanned. Can take single port (x), comma separated list of ports (x,y,z), or range of ports (x-y)
speed: Time allowed for socket to make connection. Set with T1, T2, or T3. (T1 = fast. T2 = normal. T3 = slow.)
print: Denotes if results are to be printed to pdf. Set with 'oF-yes' to print out scan results file to the local directory.


To run this tool:

1. Download port_scan_script.py
2. Navigate to the download location in the terminal.
3. Run it according to the usage above.

Example Usage:

python port_scan_script.py tcp x.x.x.x 1-100 T1 

python port_scan_script.py tcp x.x.x.x-y.y.y.y 20-25 T2 oF-yes

python port_scan_script.py tcp x.x.x.x/y 22 T2


Note: This script is built with extensive error checking on the passed in IP addresses. It will not let you run a scan against A CIDR block suffix less than 16.