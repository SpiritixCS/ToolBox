import csv
import nmap
import requests
import subprocess
import ipaddress
import sys
import argparse
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
    net_fullscan_asking = input(ENDC + "Souhaitez vous effecture un scan en profondeur pour chauqe hote découvert ? (O/n)").lower()

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
        scanner.scan(adresse_ip, arguments='-T5 -Pn -p 8888')
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
def better_scan(adresse_ip, result_list):
    scanner_ports = nmap.PortScanner()
    arguments = '-A -p ' + ','.join(map(str, result_list))
    scanner_ports.scan(adresse_ip, arguments=arguments)
    report = []

    for port in result_list:
        if 'tcp' in scanner_ports[adresse_ip]:
            port_info = scanner_ports[adresse_ip]['tcp'][port]
            cpe = port_info.get('cpe', 'N/A')

            if 'linux' in cpe.lower() or 'windows' in cpe.lower():
                cpe = ''
            
            report_entry = {
                'Port': port,
                'State': port_info['state'],
                'Service': port_info['name'],
                'Version': port_info['version'],
                'CPE': cpe,
                'CVEs': []
            }

            if cpe:
                cves = get_cves_from_nvd(cpe)
                report_entry['CVEs'] = cves
                print("CVEs:")
                cves_with_scores = []
                for cve in cves:
                    cvss_score = get_cvss_score(cve)
                    cves_with_scores.append((cve, cvss_score))
                cves_with_scores.sort(key=lambda x: (x[1] is None, x[1] if x[1] is not None else float('inf')), reverse=True)  # Sort CVEs by CVSS score in descending order, handling None values
                for cve, cvss_score in cves_with_scores:
                    print(f"CVE: {cve} (CVSS Score: {cvss_score})")

            report.append(report_entry)
    print(report_entry)
    
    if 'http' in  cpe.lower() or 'httpd' in cpe.lower() or 'http' in (report_entry['Service']) or 'httpd' in (report_entry['Service']):
        http_enum(adresse_ip, port)

    return report


def network_fullscan(net_fullscan, hosts_list):
    result_dict_nw = {}  # Dictionnaire pour stocker les ports découverts pour chaque adresse IP

    if net_fullscan == True:
        print("ok")
        # Create a tqdm progress bar with the total number of hosts
        print(BLUE + f"Début du scan de ports sur {len(hosts_list)} hôtes" + ENDC)
        with tqdm(total=len(hosts_list)) as pbar:
            for hote in hosts_list:
                scanner = nmap.PortScanner()
            
                try:
                    scanner.scan(hote, arguments='-T5 -Pn -p 8000,8080')
                except nmap.PortScannerError as e:
                    print("Erreur lors de l'analyse de l'adresse IP :", e)
                    return None, None

                for host in scanner.all_hosts():
                    if 'tcp' in scanner[host]:
                        for port in scanner[host]['tcp'].keys():
                            state = scanner[host]['tcp'][port]['state']
                            if state == 'open':
                                if host not in result_dict_nw:
                                    result_dict_nw[host] = []  # Initialise une liste vide pour cette adresse IP
                                result_dict_nw[host].append(port)

                # Update the progress bar
                pbar.update(1)

            print(f"\n")
        print(result_dict_nw)
    else:
        try:
            raise ValueError(RED + "❌ Pas de scans avancés des hôtes.")
        except ValueError as ve:
            print(ve)
            sys.exit(1)

                 


# Function to perform HTTP enumeration
def http_enum(adresse_ip, port):
    dirb_result_final = []
    dirb_result_str = ""
    print (GREEN + f"Début de l'énumération web pour http://{adresse_ip}:{port}")
            
    command = f"dirb http://{adresse_ip}:{port} ~/Applications/dirb222/wordlists/common.txt"
    dirb_result = subprocess.check_output(command, shell=True, text=True)
    filename = f"dirb-{adresse_ip}.txt"
    for line in dirb_result.splitlines():
        if "CODE" in line:
            dirb_result_final.append(line)

    dirb_result_str = ' '.join(dirb_result_final)
    dirb_final = dirb_result_str.replace("+", "\n+")
    with open(filename, "w") as file:
        file.write(dirb_final)
    if dirb_final == "":
        print(RED + "No directory found.\n" + ENDC )
    else: 
        print(dirb_final)


# Function to retrieve CVEs from NVD
def get_cves_from_nvd(cpe):
    url = 'https://services.nvd.nist.gov/rest/json/cves/1.0'
    params = {
        'cpeMatchString': cpe
    }

    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        data = response.json()
        cve_entries = data.get('result', {}).get('CVE_Items', [])
        cves = [entry['cve']['CVE_data_meta']['ID'] for entry in cve_entries]
        return cves
    except requests.exceptions.RequestException as e:
        print(RED + f"Error: {e}" + ENDC)
        return []


# Function to retrieve CVSS score for a CVE
def get_cvss_score(cve):
    url = f'https://services.nvd.nist.gov/rest/json/cve/1.0/{cve}'
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        cvss_v3_score = data.get('result', {}).get('CVE_Items', [])[0].get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore')
        if cvss_v3_score is None:
            cvss_v2_score = data.get('result', {}).get('CVE_Items', [])[0].get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {}).get('baseScore')
            return cvss_v2_score
        return cvss_v3_score
    except requests.exceptions.RequestException as e:
        print(RED + f"Error: {e}" + ENDC)
        return None


# Function to export the scan report to a CSV file
def export_to_csv(report, adresse_ip):
    export_report = input("Souhaitez-vous exporter le rapport dans un fichier CSV ? (o/n)\n")
    if export_report.lower() == 'o':
        filename = adresse_ip + ".csv"

        with open(filename, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['Port', 'State', 'Service', 'Version', 'CPE', 'CVE', 'CVSS Score'])

            for port_info in report:
                cves = port_info['CVEs']
                if cves:
                    cves_with_scores = []
                    for cve in cves:
                        cvss_score = get_cvss_score(cve)
                        cves_with_scores.append((cve, cvss_score))
                    cves_with_scores.sort(key=lambda x: (x[1] is None, x[1] if x[1] is not None else float('inf')), reverse=True)  # Sort CVEs by CVSS score in descending order, handling None values
                    for cve, cvss_score in cves_with_scores:
                        # Include the CPE in the CSV
                        writer.writerow([port_info['Port'], port_info['State'], port_info['Service'], port_info['Version'], port_info['CPE'], cve, cvss_score])
                else:
                    # If there are no CVEs, write an empty row with the port information and CPE
                    writer.writerow([port_info['Port'], port_info['State'], port_info['Service'], port_info['Version'], port_info['CPE'], '', ''])

        print(GREEN + "\nLe rapport a été exporté dans le fichier CSV.")



display_banner()
scan_type = choose_scan_type()

if scan_type == "r":
    network_range = ask_ip_range(scan_type)
    hosts_list = network_simple_scan(network_range)
    net_fullscan = net_fullscan_ask()
    if net_fullscan == True:
        network_fullscan(net_fullscan,hosts_list)


else:
    adresse_ip = ask_ip_range(scan_type)
    result_list = simple_scan()

    #Perform the detailed scan and export results to CSV
    report = better_scan(adresse_ip, result_list)
    export_to_csv(report, adresse_ip)
