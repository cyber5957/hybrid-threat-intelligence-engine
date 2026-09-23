import re

alert = "The endpoint is connected to 185.220.1.3"

pattern = r"\b\d{1,3}(?:\.\d{1,3}){3}\b"

ip_address = re.findall(pattern, alert)

print(ip_address)
