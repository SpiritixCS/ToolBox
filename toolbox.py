import csv
import nmap
import requests

def simple_scan():
    adresse_ip = input("Entrez une adresse IP : ")
    result_list = []  # Create an empty list for storing open ports
    scanner = nmap.PortScanner()

    scanner.scan(adresse_ip, arguments='-T5 -Pn -p7999-8001')

    for host in scanner.all_hosts():
        print(f"Résultats de l'analyse pour l'IP : {host}")
        if 'tcp' in scanner[host]:
            for port in scanner[host]['tcp'].keys():
                state = scanner[host]['tcp'][port]['state']
                if state == 'open':
                    result_list.append(port)  # Add open port to the list

    print(result_list)  # Print the list of open ports
    return adresse_ip, result_list

def better_scan(adresse_ip, result_list):
    scanner_ports = nmap.PortScanner()
    arguments = '-A -p ' + ','.join(map(str, result_list))
    scanner_ports.scan(adresse_ip, arguments=arguments)  # Perform an aggressive scan on the specific open ports
    report = []  # List to store the port scan report

    for port in result_list:
        print(f"Résultats de l'analyse pour le port : {port}")
        if 'tcp' in scanner_ports[adresse_ip]:
            port_info = scanner_ports[adresse_ip]['tcp'][port]  # Get all the information for the port
            cpe = port_info.get('cpe', 'N/A')  # Get the CPE information or use 'N/A' if not available

            # Check if the CPE contains "linux" or "windows" and make it empty if it does
            if 'linux' in cpe.lower() or 'windows' in cpe.lower():
                cpe = ''

            report_entry = {
                'Port': port,
                'State': port_info['state'],
                'Service': port_info['name'],
                'Version': port_info['version'],
                'CPE': cpe,  # Add the CPE information to the report
                'CVEs': []  # Initialize the CVEs list for the report entry
            }

            print(f"Port: {port}")
            print(f"State: {port_info['state']}")
            print(f"Service: {port_info['name']}")
            print(f"Version: {port_info['version']}")
            print(f"CPE: {cpe}")

            if cpe:  # Retrieve and display the CVEs for the CPE if it's not empty
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
    print(report)
    return report


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
        print(f"Error: {e}")
        return []

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
        print(f"Error: {e}")
        return None

def export_to_csv(report, adresse_ip):
    export_report = input("Souhaitez-vous exporter le rapport dans un fichier CSV ? (oui/non) ")
    if export_report.lower() == 'oui':
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

        print("Le rapport a été exporté dans le fichier CSV.")



adresse_ip, result_list = simple_scan()  # Assign the returned values from simple_scan to variables

report = better_scan(adresse_ip, result_list)  # Use the variables as arguments for better_scan and get the report

export_to_csv(report, adresse_ip)  # Ask user and export results to CSV using the report