import csv
import requests
import subprocess
from bs4 import BeautifulSoup
import ssl
import socket
import warnings
from urllib3.exceptions import InsecureRequestWarning

# Funktion zur Überprüfung eines Ports
def check_port(ip, port, protocol):
    if protocol == 'http':
        url = f'http://{ip}:{port}'
    elif protocol == 'https':
        url = f'https://{ip}:{port}'
    else:
        return 'Unbekanntes Protokoll'
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'})


    try:
        response = session.get(url, timeout=1.2, allow_redirects=True, verify=False)
        soup = BeautifulSoup(response.content, 'html.parser')  
        title = soup.find('title').text if soup.find('title') else '-'  
            
        cert_present = '-'
        if protocol == 'https':
            try:
                # Versuch, eine SSL-Verbindung aufzubauen und das Zertifikat zu erhalten
                context = ssl.create_default_context()
                with socket.create_connection((ip, port)) as sock:
                    with context.wrap_socket(sock, server_hostname=ip) as ssock:
                        cert = ssock.getpeercert()
                        cert_present = 'Ja' if cert else 'Nein'
            except Exception as e:
                cert_present = 'Nein'


        if response.status_code == 301 and protocol == 'http':
            return ('Nein', 'Ja', title,cert_present)
        elif response.status_code in [200, 401]:
            return ('Ja', 'Ja', title,cert_present)
        else:
            return ('Nein', 'Nein', "-",cert_present)
    except requests.exceptions.RequestException:
        return ('Nein', 'Nein', "-","Nein")
    finally:
        session.close()

# Hauptprogramm
def main():
    warnings.simplefilter('ignore', InsecureRequestWarning)
    with open('results.csv', 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile, delimiter=';')
        csvwriter.writerow(['IP Adresse', 'Port 80', 'Port 443', 'Zertifikat vorhanden', 'System', 'ICMP ECHP', 'HTTP redirect auf HTTPS'])

        for i in range(1, 256):
            ip = f'192.168.116.{i}'

            ping_process = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            reachable = 'Ja' if ping_process.returncode == 0 else 'Nein'

            port80, redirect,system80,_ = check_port(ip, 80, 'http')
            port443, _,system443,certAvailable = check_port(ip, 443, 'https')
            system = system80 if system80 != '-' else system443
            system = system.strip()
            if redirect == 'Ja':
                port80 = 'Nein'
            # Schreibe Ergebnisse in CSV
            csvwriter.writerow([ip, port80, port443, certAvailable, system, reachable, redirect])
            print(f'IP: {ip} -- done')

if __name__ == "__main__":
    main()