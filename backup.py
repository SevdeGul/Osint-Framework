import socket
import requests
import pandas as pd
import requests, json
import numpy as np
import threading
from bs4 import BeautifulSoup
from colorama import Fore, Style
import queue
import dns.resolver
import asyncio
import dns.asyncresolver
from emailfinder.extractor import *
import concurrent.futures

print(Style.BRIGHT + f"""{Fore.RED}
    Welcome to Attack Surface Discovery tool...
{Style.RESET_ALL}""")

#kullanıcıdan alınan domain bilgisinden ip discovery aşaması gerçekleştirilir.
def ip_bulma(domain):
    ip = socket.gethostbyname(domain)
    print("*" * 30)
    print(f"{Fore.BLUE}IP Address: \n{Style.RESET_ALL}" + ip)
    return ip 

# wordlist.txt'yi okuyarak orada yer alan kelimeler için subdomain dns brute force yapar

def dns_sorgusu(domain, wordlist, dns_server):
    for word in wordlist:
        word = word.strip()
        try: 
            subdomain = word + "." + domain
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [dns_server]
            answer = resolver.resolve(subdomain, 'A')
            print(subdomain)
        except Exception:
            continue

def subdomain_enum_dns_brute(domain, dns_servers):
    print(f"{Fore.BLUE}[i] DNS Brute force started.{Style.RESET_ALL}")
    dosya = "wordlists_shuffled.txt"
    thread_count = 3 * len(dns_servers)  # Her DNS sunucusu için 3 iş parçacığı
    threads = []  # İş parçacıkları için liste
    
    # Her iş parçacığına eşit şekilde bölünmüş wordlist oluşturuyoruz
    with open(dosya, "r", encoding='utf-8') as dosya:
        wordlist = dosya.readlines()

    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
        for i, dns_server in enumerate(dns_servers):
            start = i * len(wordlist) // thread_count
            end = (i + 1) * len(wordlist) // thread_count
            thread_wordlist = wordlist[start:end]

            # Her iş parçacığı için bir Thread oluşturun
            thread = executor.submit(dns_sorgusu, domain, thread_wordlist, dns_server)
            threads.append(thread)
    
    print(f"{Fore.BLUE}[i] Threads generated. Starting.{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] DNS Brute Force results:{Style.RESET_ALL}")
    print(f"{Fore.GREEN}-{Style.RESET_ALL}" * 30)
    # İş parçacıklarının tamamlanmasını bekleyin
    concurrent.futures.wait(threads)
    print(f"{Fore.BLUE}[i] DNS Brute force completed.{Style.RESET_ALL}")
    
#bulunan ip adresi ile subnet enumeration aşamasi yapilir.
def subnet_enumeration(ip):
    print(f"{Fore.BLUE}[i] Enumerating subnet...{Style.RESET_ALL}")
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
    print(f"{Fore.GREEN}Subnets: {Style.RESET_ALL}")
    veri = {
        'ASN No' : asns,
        'Subnets' : subnets,
        'Descriptions' : descriptions
    }

    tablo = pd.DataFrame(veri)
    return tablo

#subdomain enumeration aşamasi
def subdomain_enumeration(domain):
    print(f"{Fore.BLUE}[i] Checking SSL Transparency logs for subdomain enumeration...{Style.RESET_ALL}")
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
    print(f"{Fore.GREEN}[+] SSL Transparency scanner finished. Detected subdomains:{Style.RESET_ALL}")
    print(f"{Fore.GREEN}-{Style.RESET_ALL}"*30)
    veri = {
        '' : liste,
    }

    tablo = pd.DataFrame(veri)
    return tablo


#verilen ipleri q'dan bir port alarak tarar, açık olanları listeye ekler.
def scan(q, ip):
    global global_http_ports
    global global_open_http_ports
    global global_https_ports
    global global_open_https_ports

    while not q.empty():
        port = q.get()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            result = sock.connect_ex((ip, port))
            if port in global_http_ports:
                if result == 0:
                    global_open_http_ports.append(int(port))
            elif port in global_https_ports:
                if result == 0:
                    global_open_https_ports.append(int(port))
            sock.close()
        except socket.error:
            print("Error")
        q.task_done()

#scan fonksiyonu kullanılarak multithreading aşaması yapılır.
def port_scan(ip):
    print(f"{Fore.BLUE}[i] Scanning ports...{Style.RESET_ALL}")
    http_q = queue.Queue()
    https_q = queue.Queue()

    # Queue'yi http portlarıyla dolduruyoruz
    for i in global_http_ports:
        http_q.put(i)
    for i in global_https_ports:
        https_q.put(i)
    

    # İşi yapacak olan threadleri oluşturup listede tutuyoruz.
    threads = []
    for i in range(len(global_http_ports)):
        worker = threading.Thread(target=scan, args=(http_q, ip))
        worker.start()
        threads.append(worker)

    for i in range(len(global_https_ports)):
        worker = threading.Thread(target=scan, args=(https_q, ip))
        worker.start()
        threads.append(worker)

    # Tüm thread'lerin bitmesini bekleyelim
    for thread in threads:
        thread.join()

    print(f"{Fore.GREEN}[+] Open HTTP/HTTPS Ports: {Style.RESET_ALL}")
    veri = {
        'HTTP Ports' : global_open_http_ports
    }

    tablo = pd.DataFrame(veri)
    veri2 = {
        'HTTPS Ports' : global_open_https_ports
    }

    tablo2 = pd.DataFrame(veri2)
    return tablo, tablo2



def mail_bulma(domain):
    print(f"{Fore.BLUE}[i] Scanning email addresses...{Style.RESET_ALL}")
    emails1 = get_emails_from_google(domain)
    emails2 = get_emails_from_bing(domain)
    emails3 = get_emails_from_baidu(domain)
    emails = emails1 + emails2 +  emails3
    return emails

def main():
    print(f"{Fore.GREEN}Enter Domain: {Style.RESET_ALL}")
    domain = input()
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
    emails = mail_bulma(domain)
    print(f"{Fore.GREEN}[+] Detected email addresses:{Style.RESET_ALL}")
    print(f"{Fore.GREEN}-{Style.RESET_ALL}" * 30)
    for email in emails:
        print(email)
    print("*" * 30)
    #asyncio.run(subdomain_enum_dns_brute_async(domain))
    subdomain_enum_dns_brute(domain, global_dns_servers)


global_http_ports = [80, 81, 82,  554,  591, 4791, 5554,  5060,  5800, 5900, 6638,  8008,  8080, 8081, 8181, 8090, 8554]
global_open_http_ports = []
global_https_ports = [443, 8443]
global_open_https_ports = []
global_dns_servers = []

if __name__ == "__main__":
    with open("dns_servers.txt", "r", encoding='utf-8') as dosya:
        dnslist = dosya.readlines()
    for dns_elem in dnslist:
        clear_dns = dns_elem.strip()
        global_dns_servers.append(clear_dns)
        
    main()
