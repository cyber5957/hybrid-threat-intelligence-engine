import re 

def extract_iocs(text):
    m = re.findall(r'[\w,-]+://[\w.,-]+',text)
    n = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text)
    o = re.findall(r'[a-fA-F0-9]{32}',text)

    for label, items in [("URL", m), ("IP", n), ("Hash", o)]:
        seen = set()
        unique = []
        for item in items:
            if item not in seen:
                seen.add(item)
                unique.append(item)
        for u in unique:
            print(f"{label}: {u}")
    if not o:
            print("NO HASH")
    else:
         print("hash value: ", o)
   
        

text = """""Alert: User clicked http://secure-login-update.com from IP 185.220.101.45.
Firewall: blocked 185.220.101.45 outbound."""

extract_iocs(text)

