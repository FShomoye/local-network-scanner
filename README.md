# Local Network Scanner

A Python tool to scan your local subnet to identify online hosts, open TCP ports, identify Mac addresses using ARP table and identify the vendor of the network interface of any online host

## Features
- Automatically detects your loacal subnet (assuming it is a /24 subnet)
- Scans hosts in the subnet for availability by checking TCP port 80
- Performs port scanning on common TCP ports
- Retrieves MAC addresses using ARP and ping commands
- Identifies device vendors using the MAC address prefix via the 'mac-vendor-lookup' python library
- Uses threading to speed up network scanning.

##Requirements

-mac-vendor-lookup 
    - https://pypi.org/project/mac-vendor-lookup/
