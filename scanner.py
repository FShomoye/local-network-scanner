#Importing necessary libraries
import ipaddress
import socket

#Allows you to scan multiple devices at once (uses threads)
import concurrent.futures

import subprocess
import platform 
import re

from mac_vendor_lookup import MacLookup

#Function to check if an individual IP address is online
def is_host_online(ipaddress):
    try:
        #attempt to connect to port 80
        socket.setdefaulttimeout(1)#After 1 second, give up on connecting
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)#AF_INET specifies IPv4 socket and SOCK_STREAM sets the socket type to TCP
        result = s.connect_ex((str(ipaddress), 80))#Returns 0 if connection successful
        s.close()
        return result == 0 #if successful connection -  assume host is online
    except:
        return False
    
#Scans the subnet and appends the online hosts to a list and displays to the user the number of online hosts
def scan_subnet(subnet):
    try:
        network = ipaddress.ip_network(subnet, strict = False)#Parse through the subnet
    except ValueError:
        print("invalid Subnet format")
        return
        
    print(f"Scanning the subnet {subnet}")
    hosts_online = []

    #use of threading to scan multiple IPs faster
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_ip = {}
        for ip in network.hosts():#iterates through IPs in given subnet
            future = executor.submit(is_host_online, ip)
            future_to_ip[future] = ip

        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                if future.result():
                    print(f"Host {ip} is online")
                    hosts_online.append(str(ip))
            except Exception as error:
                print(f"Error in checking {ip}: {error}")

    print(f"Scan complete - {len(hosts_online)} hosts are online")
    return hosts_online

#Scanning for open ports on online Hosts
def scan_ports(ip):
    open_ports = []
    ports_to_scan = [20,21,22,23,25,53,80,110,139,143,443,445,993,995,1433,1521,3306,3389,5900,8080]#Most commonly used TCP ports
    try:
        for port in ports_to_scan:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((ip,port))
            s.close()
            if result == 0:
                open_ports.append(port)#
        print(f"Open ports on IP address {ip}: {open_ports}")
        return open_ports
    except Exception as error:
        print(f"Error scanning ports on {ip}: {error}")
        return False

#MAC address retrieval
def get_mac_Address(ip):
    try:
        
        if platform.system().lower() == "windows":
            #Ping the IP address to ensure it is in the ARP table
            subprocess.call(["ping", "-n", "1",ip])

            #Gets ARP table -> maps Ip addresses to MAC addresses
            output = subprocess.check_output(f"arp -a {ip}",shell=True).decode()
            

            #ensures mac addresses are in the right format, maps 2 hex digits 5 times with a colon 
            # after and then 2 more with no colon for the final 2 digit section of the mac address
            mac_regex = r"(([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2})"
        
        else:
            #Ping for non-Windows OS
            subprocess.call(["ping", "-c","1", ip])

            #For linux & macOS
            output = subprocess.check_output(["arp", "-n", ip]).decode()
            mac_regex = r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"

        
        match = re.search(mac_regex, output)

        if match:
            print(f"MAC address for {ip}: {match.group(0)}")
            return match.group(0)
        
        else:
            return "MAC address not found"
        
    except subprocess.CalledProcessError as error:
        return f"Could not retrieve MAC address for {ip}  error: {error}"
#Identifying Device type using MAC addresses
#Finding the MAC address of the device

get_mac_Address("192.168.1.254")
#IMPORTANT note your machine does not store a ARP entry for its own Networ interfece, so you will not be able to retrieve the MAC address of your own machine
#The more you know :)

#MacLookup().update_vendors()
# #Updates the MAC address vendor database


#identify device type based on MAC address
def identify_device_type(mac_address):
    try:
        mac_address = mac_address.replace("-",":")
        return MacLookup().lookup(mac_address)
    except:
        print("NO")
        return "Unknown Device Type"

def get_local_subnet():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCKDGRAM)
        s.connect()("8.8.8.8",80)
        local_ip = s.getsockname()[0]
        s.close()

        ip_parts = local_ip.split(".")
        subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"  # Assuming the network is a /24 subnet
        return subnet
    except Exception as error:
        print(f"Could not detect local subnet: {error}")
        return None