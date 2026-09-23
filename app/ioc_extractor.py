import re

alert = """
Connection from 185.220.101.5 detected.
Connection from 192.168.1.20 detected.
Connection from 185.220.101.5 detected again.
Connection from 10.10.10.45 detected.
Connection from 192.168.1.20 detected again.
"""
pattern = r"\b\d{1,3}(?:\.\d{1,3}){3}\b"

ip_address = re.findall(pattern, alert)

remove_duplicates = list(dict.fromkeys(ip_address))

print(remove_duplicates)
