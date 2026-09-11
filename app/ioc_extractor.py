import re 

def extract_iocs(text):
    m = re.findall(r'[\w,-]+://[\w.,-]+',text)
    print("URL: ",m[0])

    n = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text)
    print("ip address: ",n[0])

    o = re.findall(r'[a-fA-F0-9]{32}',text)
    print( "hash value: ", o[0])

text = """User clicked http://secure-login-update.com from IP 185.220.101.45.
File hash observed: d41d8cd98f00b204e9800998ecf8427e"""

extract_iocs(text)

