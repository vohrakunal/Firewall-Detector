import requests
import re
from urllib.parse import quote_plus

que = '\033[94m[  -  ]\033[0m'
error = '\033[91m[ Error ]\033[0m'
warn = '\033[93m[ Warning ]\033[0m'
ok = '\033[32m[ Pass ]\033[0m'


def firewall_detect(url, param_data, method, stringcheck, cookie):
    global firewall_global
    firewall_global = False
    print('%s Checking for firewall' %que)
    print('%s Sending a Script : <script>alert()</script>' %que)
    noise = quote_plus('<script>alert()</script>')
    # print(param_data)
    fuzz = param_data.replace(stringcheck, noise) #Replaces stringcheck in param_data with noise
    # print(fuzz)
    if method == 'GET':
        response = requests.get(url + fuzz, cookies=cookie) # Opens the noise injected payload
    else:
        response = requests.post(url, data=fuzz, cookies=cookie) # Opens the noise injected payload
        # print (response)

    code = str(response.status_code)
    response_str = str(response)
    # print("%sresponse : " %warn + response_str)
    # print("%scode : " %warn + code)

    response_headers = str(response.headers)
    # print("%sresponse_headers : " %warn + response_headers)
    response_text = response.text.lower()
    # print("%sresponsetext : " %warn + response_text)
    if code[:1] != '2':
        if '406' == code or '501' == code: # if the http response code is 406/501
            firewall_global_Name = 'Mod_Security'
            firewall_global = True
        elif 'wordfence' in response_text:
            firewall_global_Name = 'Wordfence'
            firewall_global = True
        elif '999' == code: # if the http response code is 999
            firewall_global_Name = 'WebKnight'
            firewall_global = True
        elif 'has disallowed characters' in response_text:
            firewall_global_Name = 'CodeIgniter'
            firewall_global = True
        elif '<hr><center>nginx</center>' in response_text:
            firewall_global_Name = 'nginx'
            firewall_global = True
        elif 'comodo' in response_text:
            firewall_global_Name = 'Comodo'
            firewall_global = True
        elif 'sucuri' in response_text:
            firewall_global_Name = 'Sucuri'
            firewall_global = True
        elif '419' == code: # if the http response code is 419
            firewall_global_Name = 'F5 BIG IP'
            firewall_global = True
        elif 'barra' in response_headers:
            firewall_global_Name = 'Barracuda'
            firewall_global = True
        elif re.search(r'cf[-|_]ray', response_headers):
            firewall_global_Name = 'Cloudflare'
            firewall_global = True
        elif 'AkamaiGHost' in response_headers:
            firewall_global_Name = 'AkamaiGhost'
            firewall_global = True
        elif '403' == code: # if the http response code is 403
            firewall_global_Name = 'Unknown'
            firewall_global = True
    else:
        print('%s No Firewall Detected | Firewall Status : Offline' % ok)
        return False
    if firewall_global:
        print('%s Firewall Online | Firewall Type : %s' % (warn, firewall_global_Name))
        return True
