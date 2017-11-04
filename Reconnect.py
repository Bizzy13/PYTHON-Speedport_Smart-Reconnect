## Speedport Smart Reconnect
##
## INSTALL INSTRUCTION
##
## Windows:
##    - Download Python 2.7                                                                      https://www.python.org/ftp/python/2.7.14/python-2.7.14.msi
##    - Install Python 2.7 under C:\Python27\
##    - Download pycryptodome-3.4.7-cp27-cp27m-win32.whl and save it directly under C:\          https://pypi.python.org/simple/pycryptodome/
##    - Open the command prompt and type in the following commands
##          cd C:\Python27\Scripts
##          pip install C:\pycryptodome-3.4.7-cp27-cp27m-win32.whl
##    - JDownloader Settings
##          Reconnect method -> External Batch Reconnect
##          Interpreter -> C:\Python27\python.exe
##          Batch-Script -> C:\PATH_TO_RECONNECT_SCRIPT\Reconnect.py
##
## Linux:
##    - Python 2.7 (In the most Linux Distributions already included)
##    - Download pycryptodome-3.4.7.tar.gz                                                      https://pypi.python.org/simple/pycryptodome/
##    - Open the Terminal and type in the following command
##          sudo pip install /PATH_TO_THE_DOWNLOADED_FILE/pycryptodome-3.4.7.tar.gz
##    - JDownloader Settings
##          Reconnect method -> External Batch Reconnect
##          Interpreter -> /usr/bin/python
##          Batch-Script -> /PATH_TO_RECONNECT_SCRIPT/Reconnect.py
##

##
## CONFIG
##

device_password  =  "PASSWORD"              # The device password for login
speedport_url    =  "http://speedport.ip/"  # The URL to the Speedport Smart Configurator
Sleeptime = 5                               # If the Reconnect don't work, change the number to 10 and then try again

##
## DO NOT CHANGE ANYTHING BELOW THIS LINE
##

from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
import time
import sys
import socket
import json
import binascii
import urllib
import urllib2
import cookielib

login_html = "html/login/index.html"
login_json = "data/Login.json"
connection_json = "/data/Connect.json"
connection_html = "html/content/internet/connection.html"
challenge_val = ""
derivedk = ""

http_header = {"Content-type": "application/x-www-form-urlencoded", "charset": "UTF-8"}
cookies = cookielib.CookieJar()
opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cookies))
socket.setdefaulttimeout(7)

# URL has to end with slash
if not speedport_url.endswith("/"):
    speedport_url += "/"

# Gets the challenge_val token from login page
def get_challenge_val():
    global challenge_val
    
    print("Extracting Random-Key...")

    challenge_val = extract(speedport_url + login_html, 'challenge = "', '";')
    
    if not bool(challenge_val):
        sys.exit("Couldn't extracting Random-Key successfully from " + speedport_url + login_html)
    else:
        print("Random-Key: "+ challenge_val)

# Login with devices password
def login():
    global derivedk
    
    print ("Logging in...")
	
    # Hash password with challenge_val
    sha256_full = SHA256.new()
    sha256_full.update("%s:%s" % (challenge_val, device_password))
    encrypted_password = sha256_full.hexdigest()

    # Hash only password
    sha256_passwort = SHA256.new()
    sha256_passwort.update(device_password)
    sha256_loginpwd = sha256_passwort.hexdigest()
    
    # Get hashed derivedk
    derivedk = binascii.hexlify(PBKDF2(sha256_loginpwd, challenge_val[:16], 16, 1000))
	
    # Finally login
    json_string = open_site(speedport_url + login_json, {"csrf_token": "nulltoken", "showpw": 0, "password": encrypted_password, "challengev": challenge_val})
    json_object = string_to_json(json_string)
    
    # Check valid response
    for x in json_object:
        if x["vartype"] == "status":
            if x["varid"] == "login":
                if x["varvalue"] != "success":
                    sys.exit("Failed to login at URL " + speedport_url + login_json)
            if x["varid"] == "status":
                if x["varvalue"] != "ok":
                    sys.exit("Failed to login at URL " + speedport_url + login_json)
    
    # Set needed cookies
    set_cookie("challengev", challenge_val)
    set_cookie("derivedk", derivedk)

    print("Login successful")
    
# Extract a String
def extract(url, a, b):
    html = open_site(url, None)
    start = html.find(a)

    end = html.find(b, start)
    return html[(start + len(a)) : end]

# Reconnecting the Speedport
def reconnect():
    oldIP = extract('http://api.ipify.org/?format=json', '"ip":"', '"}')
    
    csrf_token = get_csrf_token()

    print("Disconnecting...")

    # Disconnect Speedport with token
    open_site(speedport_url + connection_json, Command_Hash("req_connect=disabled&csrf_token=" + urllib.quote_plus(csrf_token)))
    
    time.sleep(Sleeptime)

    csrf_token = get_csrf_token()

    print("Connecting...")
    # Connect Speedport with token
    open_site(speedport_url + connection_json, Command_Hash("req_connect=online&csrf_token=" + urllib.quote_plus(csrf_token)))

    time.sleep(Sleeptime)

    newIP = extract('http://api.ipify.org/?format=json', '"ip":"', '"}')

    print("Old IP: " + oldIP)
    print("New IP: " + newIP)

    if oldIP == newIP:
        sys.exit("Reconnect failed")
    else:
        print("Reconnect successful")
        quit()

def get_csrf_token():
    print("Extracting csrf_token...")
    
    html = open_site(speedport_url + connection_html, None)
    start = html.find("csrf_token")
	
    # Found a crsf token?
    if start == -1:
        sys.exit("Couldn't extract csrf_token")
	
    # Get raw token
    end = html.find(";", start)
    ex = html[(start + len("csrf_token =  \"") - 1) : (end - 1)]

    print("csrf_token: " + ex)
    return ex

# Command-Hashing
def Command_Hash(data):
    
    # Hash Reconnect Command
    aes = AES.new(binascii.unhexlify(derivedk), AES.MODE_CCM, binascii.unhexlify(challenge_val[16:32]), mac_len=8)
    aes.update(binascii.unhexlify(challenge_val[32:48]))
    encrypted = aes.encrypt_and_digest(data)
	
    # Get Reconnect Command
    return binascii.hexlify(encrypted[0] + encrypted[1])

# Opens a specific site
def open_site(url, params):
    # Params only for post requests and dicts
    if params != None and type(params) is dict:
        params = urllib.urlencode(params)
	
    # Open URL
    req = urllib2.Request(url, params, http_header)
    res = opener.open(req)
	
    # Return result
    return res.read()

# Converts a string to a json object
def string_to_json(string):
    # Replace special tokens
    string = string.strip().replace("\n", "").replace("\t", "")
    
    # Some strings are invalid JSON object (Additional comma at the end...)
    if string[-2] == ",":
    	string_list = list(string)
    	string_list[-2] = ""
    	
    	return json.loads("".join(string_list))
	
    return json.loads(string)

# Sets new cookies
def set_cookie(name, value):
    cookie = cookielib.Cookie(version=0, name=name, value=value, port=None, port_specified=False, domain=speedport_url.replace("http://", "").replace("/", ""), domain_specified=False, domain_initial_dot=False, path="/", path_specified=True, secure=False, expires=None, discard=True, comment=None, comment_url=None, rest={"HttpOnly": None}, rfc2109=False)
    cookies.set_cookie(cookie)

# At first get challenge_val
get_challenge_val()

# Then login
login()

# Then Reconnecting
reconnect()
