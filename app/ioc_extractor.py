import re

def ip_validation(ip_address):
    valid_ips = []
    for ip in ip_address:
        int_list = [int(x) for x in ip.split(".")]
        if len(int_list) == 4 and all(0 <= value <= 255 for value in int_list):
            valid_ips.append(ip)
    remove_duplicates = list(dict.fromkeys(valid_ips))
    return remove_duplicates


        
alert = """
Connection from 192.168.0.1 detected.
Connection from 192.168.1.20 detected.
Connection from 185.220.101.5 detected again.
Connection from 10.10.10.45 detected.
Connection from 192.168.1.20 detected again.
"""
       
pattern = r"\b\d{1,3}(?:\.\d{1,3}){3}\b"


ip_address = re.findall(pattern, alert)

clean_ips = ip_validation(ip_address)


