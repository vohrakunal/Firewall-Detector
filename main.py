que = '\033[94m[  -  ]\033[0m'
error = '\033[91m[ Error ]\033[0m'
warn = '\033[93m[ Warning ]\033[0m'
ok = '\033[32m[ Pass ]\033[0m'

import requests
import re # Module for RegEx
import sys # Standard system library
import os # Standard module for system related operations


# FOR PARSING
from urllib.parse import urlparse, parse_qs, quote_plus #Parse a query string given as a string argument (data of type application/x-www-form-urlencoded). Data are returned as a dictionary. The dictionary keys are the unique query variable names and the values are lists of values for each name.

# TIME
#from time import sleep # To pause the program for a specific time

# FIREWALL
from firewall import firewall_detect

stringcheck = 'fe890fef'
pname = [] # list for storing parameter names
pval = [] # list for storing parameter values


def main():
    global url
    target = input('%s Url: ' % que)
    cookie_val = input('%s Enter cookie value (if any): ' % que)
    cookie = {'Cookie' : cookie_val}
# CHECK IF THE URL IS HTTP OR HTTPS OR NOT HTTP/HTTPS
    if 'http' in target: # if the target has http in it, do nothing
        print('%s Found [http/https] in target!' %ok)
        pass
    else:
        print('%s Target doesnot contain [http/https]' %warn)
        print('%s Adding [http] in target' %que)
        try:
            print('%s Trying to reach target with [http]' %que)
            requests.get('http://%s' % target, cookies=cookie) # Makes request to the target with http schema
            target = 'http://%s' % target
            print('%s Target found' %ok)
        except: # if it fails, maybe the target uses https schema
            print('%s Failed to connect to target trying with [https]' %warn)
            target = 'https://%s' % target

    try:
        print('%s Trying to reach target' %que)
        requests.get(target, cookies=cookie) # Makes request to the target
    except Exception as e: # if it fails, the target is unreachable
        if 'ssl' in str(e).lower():
            target = 'http://%s' % target

        else:
            print('%s Target Unreachable' %error)
            quit()


# CHECK IF METHOD IS GET OR POST
    print('%s Checking for GET/POST method' %que)
    parsed_url = urlparse(target)
    url = parsed_url.scheme+'://'+parsed_url.netloc+parsed_url.path

    if '=' in target: # A url with GET request must have a = so...
        print('%s GET method found' %ok)
        method = 'GET'
        param_data = ''

        parameters = parse_qs(parsed_url.query, keep_blank_values=True)
        for para in parameters:
            for i in parameters[para]:
                pname.append(para)
        firewall_return = firewall_detect(url, '?'+pname[0]+'='+stringcheck, method, stringcheck, cookie)

    else:
        choice = input('%s Does it use POST method? [Y/n] ' % que).lower()
        if choice == 'n':
            print('%s No value for GET exiting' %error)
            method = 'GET'
            quit()
        else:
            print('%s Using POST method' %ok)
            method = 'POST'
            param_data = input('%s Enter POST data: ' % que)
            pparser(target, param_data, method)
            firewall_return = firewall_detect(url, param_data, method, stringcheck, cookie)
main()
