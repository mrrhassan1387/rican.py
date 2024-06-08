import requests
from termcolor import colored
import re
import whois
import socket
import argparse
from bs4 import BeautifulSoup
import dns.resolver

        
parser = argparse.ArgumentParser(description='recan ple')
parser.add_argument('--tag', type= str)
args = parser.parse_args()
if args.tag:
    v = str(args.tag)
    x = requests.get(v)
    soup = BeautifulSoup(x.text, "html.parser")
    a = soup.find_all('a')
    w = []
    e = []
    i = 0
    for q in a:
        w.insert(i, q)
        i+=1
        sdc = open("tag.txt", "a+")
        sdc.writelines(q)
        sdc.close()
        print(colored(q,"blue"))
        print("\n")
        e.append(q.get('href'))
    for d in e:
        print(colored(d,"blue"))
        print("\n")
    for c in e:
        try:
            vb = requests.get(c)
            sop  = BeautifulSoup(vb.text,"html.parser")
            wwe = sop.find_all('a')
            for hf in wwe:   
                        sdc = open("tag.txt", "a+")
                        sdc.writelines(hf)
                        sdc.close()
                        print(colored(hf,"blue"))
                        print("\n")
                        print(colored("next","blue"))
        except:
            pass
        """
elif sd == 2:
    to = int(input(colored("html namber 1" + "\n" + "txt namber 2" + "\n","green")))
    if to == 1:
        domain = input(colored("Enter your site:","green"))
        r = open('wordlist.txt','r')
        w = r.readlines()
        for subdomain in w:
            subdomain = subdomain.replace('\n','')
            try:
                dddd = subdomain
                answers = dns.resolver.query(dddd+'.'+domain, 'A')
                for ip in answers:
                        ddz = open("subdomain.html","a+")
                        ddz.write(domain + dddd + "." + domain + " - " + str(ip) + "\n")
                        ddz.close()
                        print(colored(dddd + "." + domain + " - " + str(ip), "green"))
            except:
                    print(colored("eroeo!!!","red"))
    elif to == 2:
        domain = input(colored("Enter your site:","green"))
        r = open('wordlist.txt','r')
        w = r.readlines()
        for subdomain in w:
            subdomain = subdomain.replace('\n','')
            try:
                dddd = subdomain
                answers = dns.resolver.query(dddd+'.'+domain, 'A')
                for ip in answers:
                        ddz = open("subdomain.txt","a+")
                        ddz.write(domain + dddd + "." + domain + " - " + str(ip) + "\n")
                        ddz.close()
                        print(colored(dddd + "." + domain + " - " + str(ip), "green"))
            except:
                    print(colored("eroeo!!!","red"))

elif sd == 3:
    ereeddd = int( input(colored("html namber 1" + "\n" + "txt namber 2" + "\n","light_blue")))
    if ereeddd == 1:
        v = input(colored("Enter your site:","light_blue"))
        x = requests.get(v)
        x = x.status_code
        if x == 200:
            ddz = open("status.html","a+")
            print(colored("Success!","light_blue"))
            ddz.write(v + "   " + "Success!" + "\n")
            ddz.close()
        elif x == 404:
            ddz = open("status.html","a+")
            print(colored("Page not found.","light_blue"))
            ddz.write(v +  "    " + "Page not found." + "\n")
            ddz.close()
        elif x == 500:
            ddz = open("status.html","a+")
            print(colored("Internal server error.","light_blue"))
            ddz.write(v + "   " + "Internal server error." + "\n")
            ddz.close()
        else:
            ddz = open("status.html","a+")
            print(colored("Unknown status code:" +  x ,"light_blue"))
            ddz.write(v + "   " + "Unknown status code:" + "\n")
            ddz.close()
    elif ereeddd == 2:
        v = input(colored("Enter your site:","light_blue"))
        x = requests.get(v)
        x = x.status_code
        if x == 200:
            ddz = open("status.txt","a+")
            print(colored("Success!","light_blue"))
            ddz.write(v + "   " + "Success!" + "\n")
            ddz.close()
        elif x == 404:
            ddz = open("status.txt","a+")
            print(colored("Page not found.","light_blue"))
            ddz.write(v +  "    " + "Page not found." + "\n")
            ddz.close()
        elif x == 500:
            ddz = open("status.txt","a+")
            print(colored("Internal server error.","light_blue"))
            ddz.write(v + "   " + "Internal server error." + "\n")
            ddz.close()
        else:
            ddz = open("status.txt","a+")
            print(colored("Unknown status code:" +  x ,"light_blue"))
            ddz.write(v + "   " + "Unknown status code:" + "\n")
            ddz.close()


elif sd == 4:
url = input(colored("Enter your site:","cyan"))
response = requests.get(url)
soup = BeautifulSoup(response.text, 'html.parser')
title = soup.title.string
print(colored(title,"cyan"))
elif sd == 5:
    urls = input(colored("Enter your site:","magenta"))
    sddf = whois.whois(urls)
    print(colored(sddf,"magenta"))
elif sd == 6:
    kro = input(colored("Enter your site:","dark_grey"))
    texts = requests.get(kro)
    pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    email = re.search(pattern, texts.text)
    if email:
        print(colored(email.group(),"dark_grey"))
    else:
        print(colored("No email found","red"))
elif sd == 7:
    ertpg = input(colored("Enter your site:","light_red"))
    tel = requests.get(ertpg)
    pat = r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"
    gpat = re.search(pat,tel.text)
    if gpat:
        print(colored(gpat.group(),"light_red"))
    else:
        print(colored("No phone found","red"))
elif sd == 8:
    rssx = open('wordlist.txt','r')
    wer = rssx.readlines()

    domain = "digikala.com"
    ip_address = socket.gethostbyname(domain)
    print(f"The IP address of {domain} is {ip_address}")
elif sd == 9:
    ip = input(colored("Enter your site:","light_yellow"))
    common_ports = [21, 22, 23, 25, 53, 80, 110, 119, 123, 143, 161, 194, 443, 445, 993, 995]

    for port in common_ports:  
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(4)
        result = sock.connect_ex((ip, port))
        if result == 0:
            print("Port {} is open".format(port))
        else:
            print("Port {} is closed".format(port))
        sock.close()
"""