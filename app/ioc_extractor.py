import re

def ip_validation(ip_address):
    valid_ips = []
    for ip in ip_address:
        int_list = [int(x) for x in ip.split(".")]
        if len(int_list) == 4 and all(0 <= value <= 255 for value in int_list):
            valid_ips.append(ip)
    remove_duplicates = list(dict.fromkeys(valid_ips))
    return remove_duplicates

def domain_extractor(extractor):
    for domain in extractor:
        tld = domain.split(".")[-1]
        if not tld.isdigit():
            print("valid")
        else:
            reject 



        
alert = """
google.com
evil-example.com
login.evil-example.com
192.168.1.20
hello
example.
"""
       
#pattern = r"\b\d{1,3}(?:\.\d{1,3}){3}\b"

domain_regrex = r"\b[a-zA-Z0-9-]+(?:\.[[a-zA-Z0-9-]+)+\b"

extractor = re.findall(domain_regrex, alert)
domain_extractor(extractor)



"""ip_address = re.findall(pattern, alert)

clean_ips = ip_validation(ip_address)"""


