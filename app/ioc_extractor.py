import re 

text = """User clicked http://secure-login-update.com from IP 185.220.101.45.
File hash observed: d41d8cd98f00b204e9800998ecf8427e"""

m = re.findall(r'[\w,-]+://[\w,-]+',text)
print("URL: ",m)

