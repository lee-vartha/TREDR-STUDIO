#allows me to run external programs
import subprocess
# lets me interact with the operating system
import os
# needing this to have an interface to different hash algorithms (mostly just using SHA256)
import hashlib
# to interact with web services/make HTTP requests (GET, POST, PUT, DELETE)
import requests
# introducing concurrency for running tasks in the background
import threading
# to get current date and time
import time

YARA_PATH = "yara64.exe"
RULES_FILE = "rules\\trojan_rules.yar"
VT_API_KEY = "34923601df873108e50af7f497e636c88f6087851ca5321dde99cfebec76f509"
VT_URL = "https://virustotal.com/api/v3/files/"
UPLOAD_URL = "https://www.virustotal.com/api/v3"
DELAY = 15 # api rate limit is 1 req per 15 sec

