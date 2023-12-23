import dns.asyncresolver

def test(dns_server, subdomain): 
    try: 
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [dns_server]
        answer = resolver.resolve(subdomain, 'A')
        print(f"SUCCESS! Subdomain: {subdomain}, DNS: {dns_server}")
        
    except Exception:
        print(f"EXCEPTION - DNS: {dns_server} , Subdomain: {subdomain}")


global_dns_servers = []
with open("dns_servers.txt", "r", encoding='utf-8') as dosya:
    dnslist = dosya.readlines()
    for dns_elem in dnslist:
        clear_dns = dns_elem.strip()
        global_dns_servers.append(clear_dns)

gecerli = "bilisimsistemleri.mu.edu.tr"
gecersiz = "abcsevabc.mu.edu.tr"

for server in global_dns_servers:
    test(server, gecersiz)



