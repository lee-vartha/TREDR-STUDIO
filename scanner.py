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

def scan_folder(folder_path, output_box):
    output_box.configure(state="normal")
    output_box.delete(1.0, tk.END)
    browse_button.config(state="disabled")
    output_box.insert(tk.END, "[+] Running YARA scan...\n")
    progress_bar.start()

    yara_result = subprocess.run(
        [YARA_PATH, RULES_FILE, folder_path],
        capture_output=True,
        text=True
    )

    # yara_result.stdout represents the standard output
    # .strip() removes whitespace and 
    # .splitlines() splits output into list
    matches = yara_result.stdout.strip().splitlines()

    # if theres no match then the output box will say nothings wrong
    if not matches or matches == ['']:
        output_box.insert(tk.END, "[-] No suspicious files detected,\n")
        return

    # otherwise the box will insert
    output_box.insert(tk.END, "[+] YARA matches found: \n")
    # creates an empty set, which will list out unordered items
    suspicious_files = set()
    # for each line with the match
    for line in matches:
        #inserting "=> {line}" into the 'output_box' entry box
        # tk.END is showing the position on where the text should go - this goes at the end of the context of this string
        output_box.insert(tk.END, f"=> {line}\n")
        parts = line.split()
        # if the length of everything is more than 2 then add the second element
        if len(parts) >= 2:
            suspicious_files.add(parts[1])

    # in the same entry box, add 'Checking VirusTotal'
    output_box.insert(tk.END, "\n[+] Checking VirusTotal... \n")

    # working with the API and inserting the headers
    headers = {"x-apikey": VT_API_KEY}


    for file_path in suspicious_files:
        output_box.insert(tk.END, f"\n => {file_path}\n")
        try:
            # calculating the SHA256 hash 
            # open the file and read in binary mode
            with open(file_path, "rb") as f:
                file_bytes = f.read()
                sha256 = hashlib.sha256(file_bytes).hexdigest()
            response = requests.get(VT_URL + sha256, headers=headers)

            # if its successful (200)
            if response.status_code == 200:
                data = response.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                output_box.insert(tk.END, f"VT Detection: {stats['malicious']} malicious, {stats['suspicious']} suspicious\n")

            # if it failed (client error - 400)
            elif response.status_code == 404:
                output_box.insert(tk.END, "Not found in VT database. Uploading file...\n")

                files = {"file": (os.path.basename(file_path), open(file_path, "rb"))}
                upload_response = requests.post(UPLOAD_URL, headers=headers, files=files)

                if upload_response.status_code == 200:
                    analysis_id = upload_response.json()["data"]["id"]
                    output_box.insert(tk.END, f"Uploaded. Analysis ID: {analysis_id}\n Waiting for analysis ({DELAY} secs)...\n")
                    time.sleep(DELAY)

                    result = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
                    if result.status_code == 200:
                        stats = result.json()["data"]["attributes"]["stats"]
                        output_box.insert(tk.END, f"VT Detection: {stats['malicious']} malicious, {stats['suspicious']} suspicious \n")
                    else:
                        output_box.insert(tk.END, f"Couldnt retrieve results: {result.status_code}\n")
                else:
                    output_box.insert(tk.END, f"Upload failed: {upload_response.status_code}\n")
            else:
                output_box.insert(tk.END, f"VT error: {response.status_code}\n")

        except Exception as e:
            output_box.insert(tk.END, f"Error: {e}\n")

    done_scanning()

def done_scanning():
    progress_bar.stop()
    browse_button.config(state="normal")
    output_box.insert(tk.END, "\n Scan Complete.")
    output_box.configure(state="disabled")

# gui
def browse_scan():
    folder = filedialog.askdirectory()
    if folder:
        scan_folder(folder, output_box)

root = tk.Tk()
root.title("TREDR - Trojan Risk Education & Detection Resource")
root.geometry("700x500")
root.configure(bg="#f0f2f5")

title_label = tk.Label(root, text="Hybrid Trojan Detection", font=("Helvetica", 18, "bold"), bg="#f0f2f5", fg="#1a1a1a")
title_label.pack(pady=10)

desc_label = tk.Label(root, text="Choose a folder to scan for suspicious files using YARA + VirusTotal", font=("Helvetica", 10), bg="#f0f2f5")
desc_label.pack(pady=5)

frame = tk.Frame(root)
frame.pack(pady=10)

browse_button = tk.Button(frame, text="Select Folder & Scan", command=browse_scan)
browse_button.pack()

progress_bar = ttk.Progressbar(root, mode='indeterminate', length=500)
progress_bar.pack(pady=10)

output_box = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=85, height=25)
output_box.pack(padx=10, pady=10)
output_box.configure(state="disabled") # readonly

root.mainloop()