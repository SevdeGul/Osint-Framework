import socket
import requests
import pandas as pd
import requests, json
import numpy as np
import threading
from bs4 import BeautifulSoup
from colorama import Fore, Style

print(Style.BRIGHT + f"""{Fore.RED}
    Welcome to Attack Surface Discovery tool...
{Style.RESET_ALL}""")

#kullanıcıdan alınan domain bilgisinden ip discovery aşaması gerçekleştirilir.
def ip_bulma(domain):
    ip = socket.gethostbyname(domain)
    print(f"{Fore.BLUE}IP Address: \n{Style.RESET_ALL}" + ip)
    return ip 

#bulunan ip adresi ile subnet enumeration aşamasi yapilir.
def subnet_enumeration(ip):
    bgp = "https://bgp.he.net/ip/"
    url = bgp + ip
    response = requests.get(url)
    html = response.text
    soup = BeautifulSoup(html, 'html.parser')
    tbody = soup.select("#ipinfo > table > tbody")[0]
    trs = tbody.find_all("tr")

    asns = []
    subnets = []
    descriptions = []
    for tr in trs:
        tds = tr.find_all('td')

        asn = tds[0]
        subnet = tds[1].a
        description = tds[-1]

        asns.append(asn.text)
        subnets.append(subnet.text)
        descriptions.append(description.text)
    print(f"{Fore.BLUE}Subnets: {Style.RESET_ALL}")
    veri = {
        'ASN No' : asns,
        'Subnets' : subnets,
        'Descriptions' : descriptions
    }

    tablo = pd.DataFrame(veri)
    return tablo

#subdomain enumeration aşamasi
def subdomain_enumeration(domain):
    crt_sh = "https://crt.sh/?q=" +domain + "&output=json"
    subdomains = set()
    wildcardsubdomains = set()

    try:
        response = requests.get(crt_sh, timeout=25)
        if response.ok:
            content = response.content.decode('UTF-8')
            jsondata = json.loads(content)
            for i in range(len(jsondata)):
                name_value = jsondata[i]['name_value']
                if name_value.find('\n'):
                    subname_value = name_value.split('\n')
                    for subname_value in subname_value:
                        if subname_value.find('*'):
                            if subname_value not in subdomains:
                                subdomains.add(subname_value)
                        else:
                            if subname_value not in wildcardsubdomains:
                                wildcardsubdomains.add(subname_value)
    except:
        pass
    subdomain = subdomains.union(wildcardsubdomains)

    liste = list(subdomain)
    print(f"{Fore.BLUE}Subdomains: {Style.RESET_ALL}")
    veri = {
        '' : liste,
    }

    tablo = pd.DataFrame(veri)
    return tablo

#domain'den bulunan ip uzerinde http/https port taramasi yapar
def port_scan(ip):
    http_ports = [80, 81, 82,  554,  591, 4791, 5554,  5060,  5800, 5900, 6638,  8008,  8080, 8081, 8181, 8090, 8554]
    https_ports = [443, 8443]
    open_http = []
    open_https = []
    print(f"{Fore.GREEN}        PORTS SCANING...{Style.RESET_ALL}")

    for http_port in http_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            result = sock.connect_ex((ip, http_port))
            if result == 0:
                open_http.append(http_port)
            sock.close()
        except socket.error:
            print("Error")

    for https_port in https_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            result = sock.connect_ex((ip, https_port))
            if result == 0:
                open_https.append(https_port)
            sock.close()
        except socket.error:
            print("Error")
    print("*" * 30)
    print(f"{Fore.BLUE}HTTP/HTTPS Enumeration: {Style.RESET_ALL}")
    veri = {
        'HTTP Ports' : open_http
    }

    tablo = pd.DataFrame(veri)
    veri2 = {
        'HTTPS Ports' : open_https
    }

    tablo2 = pd.DataFrame(veri2)
    return tablo, tablo2

print(f"{Fore.GREEN}Enter Domain: {Style.RESET_ALL}")
domain = input()
print("*" * 30)
ip = ip_bulma(domain)
print("*" * 30)
print(subnet_enumeration(ip))
print("*" * 30)
print(subdomain_enumeration(domain))
print("*" * 30)
http_ports, https_ports = port_scan(ip)
merged_ports = pd.concat([http_ports, https_ports], axis=1)
cleaned_df = merged_ports.replace([np.nan, -np.inf], "")
print(cleaned_df)
print("*" * 30)

