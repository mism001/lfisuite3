# LFISuite: LFI Automatic Exploiter and Scanner
# Author: D35m0nd142, <d35m0nd142@gmail.com>
# Twitter: @D35m0nd142
# Python version: 3.x
# Tutorial Video: https://www.youtube.com/watch?v=6sY1Skx8MBc
# Github Repository: https://github.com/D35m0nd142/LFISuite

#!/usr/bin/python3
# -*- coding: utf-8 -*-
import os
import re
import sys
import urllib.request
import urllib.parse
import subprocess

def download(file_url, local_filename):
    web_file = urllib.request.urlopen(file_url)
    local_file = open(local_filename, 'wb')
    local_file.write(web_file.read())
    web_file.close()
    local_file.close()

def solve_dependencies(module_name, download_url=None):
    try:
        from pipper import pip_install_module
    except:
        print("[!] pipper not found in the current directory.. Downloading pipper..")
        download("https://raw.githubusercontent.com/mism001/lfisuite3/refs/heads/main/pipper.py", "pipper.py")
        from pipper import pip_install_module

    if download_url is not None:
        print("\n[*] Downloading %s from '%s'.." % (module_name, download_url))
        download(download_url, module_name)
        if sys.platform[:3] == "win":  # in case you are using Windows you may need to install an additional module
            pip_install_module("win_inet_pton")
    else:
        pip_install_module(module_name)

import time
import socket
import codecs
import base64
import urllib.request
import shutil

try:
    import requests
except:
    solve_dependencies("requests")
    import requests

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

try:
    import socks
except:
    solve_dependencies("socks.py", "https://raw.githubusercontent.com/mism001/lfisuite3/refs/heads/main/socks.py")
    import socks

import threading
from random import randint

try:
    from termcolor import colored
except:
    solve_dependencies("termcolor")
    from termcolor import colored

netcat_url = "https://github.com/mism001/lfisuite3/raw/refs/heads/main/nc.exe"
LFS_VERSION = '1.13'  # DO NOT MODIFY THIS FOR ANY REASON!!

# ... (le reste du code suit avec les mêmes modifications)

# Remplacement de tous les print sans parenthèses
# Remplacement de tous les raw_input() par input()
# Adaptation des imports et des fonctions obsolètes

def banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("""
                     .//// *,                                 ,//// *,
         .///////////*//** //            ,*. ,                ////* .                 .,, ..
,*///* /.   *//////////. .,,../         ,*/////,.*         *///*  .,,.*/////////// * ,//////./,
 .///* (,   *////    **.////,.(.       */////*,  *///* /. ./////*////,*//////////* */////*. ,#*
  ///* (,   *///*       ////,,(.       *///////*.////* (, ,////*.////,.( *///*.%% *////////* (,
 .###/ (,   */////////. ////.*(.      .. ,*//////*////./* *////*.////.*/ *///**(, /(((#####/ #,
 ,###/ (,   (########/  #### (/.        . ,####( ,####(.,(####/ ,#### (* (###.(/. .#####/*.  #,
 *###/..,/(*(###/   ** ,#### (/          /####/ * (###########  *#### (..###( #/. . *######/, *
 /########/.####**#*/( *###( #*        *#####. %(,./#######(, # (###( # *###/ #*   ., .*####/.(.
 /########/ ####,/(.   //,  (#*       ,*/((, ##/. .   ...  ,%#/ (/,  (#     /#/.      ,*  ,/./(.
 .********, /*. .#/   .*##(/,.        ,/(###(*.     .,*****,.  ./##(/,. .,**,.           .*/(/,     v 1.13
         ./#(/*.
    """)

    print("/*-------------------------------------------------------------------------*\\")
    print("| Local File Inclusion Automatic Exploiter and Scanner + Reverse Shell      |")
    print("|                                                                           |")
    print("| Modules: AUTO-HACK, /self/environ, /self/fd, phpinfo, php://input,        |")
    print("|          data://, expect://, php://filter, access logs                    |")
    print("|                                                                           |")
    print("| Author: D35m0nd142, <d35m0nd142@gmail.com> https://twitter.com/d35m0nd142 |")
    print("\*-------------------------------------------------------------------------*/\n")

# ... (continuer avec le reste des fonctions)

# À la fin du fichier, remplacer le menu principal :
banner()
check_for_update()
time.sleep(0.5)
choice = "4"
validChoice = (choice == "1" or choice == "2" or choice == "x")

while not validChoice:
    print("--------------------")
    print(" 1) Exploiter       ")
    print(" 2) Scanner         ")
    print(" x) Exit            ")
    print("--------------------")
    choice = input(" -> ")

    if choice.lower() == "x":
        exit()
    if choice == "1" or choice == "2":
        validChoice = True
        input_cookie = input("\n[*] Enter cookies if needed (ex: 'PHPSESSID=12345;par=something') [just enter if none] -> ")
        if len(input_cookie) > 0:
            gen_headers['Cookie'] = input_cookie

        use_tor = input("\n[?] Do you want to enable TOR proxy ? (y/n) ")
        if use_tor.lower() in ("y", "yes"):
            tor_addr = input("[*] Tor IP [default='127.0.0.1'] -> ") or "127.0.0.1"
            tor_port = input("[*] Tor Port [default=9150] -> ")
            try:
                tor_port = int(tor_port) if tor_port.isdigit() and 1 <= int(tor_port) <= 65535 else 9150
            except:
                tor_port = 9150
                print("[!] Invalid port! Using 9150.")

            socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, tor_addr, tor_port)
            socket.socket = socks.socksocket
            print(colored("[+] TOR proxy active on socks5://%s:%s" % (tor_addr, tor_port), "red"))
            time.sleep(0.5)

        if choice == "2":
            scanner()
        elif choice == "1":
        
