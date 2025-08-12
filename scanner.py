import subprocess
import os
import hashlib 
import requests
import time
import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk
from datetime import datetime


YARA_PATH = "yara64.exe"
RULES_FILE = "rules\\trojan_rules.yar"
VT_API_KEY = "34923601df873108e50af7f497e636c88f6087851ca5321dde99cfebec76f509"
VT_URL = "https://virustotal.com/api/v3/files/"
UPLOAD_URL = "https://www.virustotal.com/api/v3"
DELAY = 15 # api rate limit is 1 req per 15 sec

