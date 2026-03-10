import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
import requests
import socket
import whois
import threading
import os
from PIL import Image
from PIL.ExifTags import TAGS

# ----------------------------
# Main Application
# ----------------------------

class OSINTToolkit:

    def __init__(self, root):
        self.root = root
        self.root.title("OSINT Recon Toolkit")
        self.root.geometry("900x600")

        title = tk.Label(root, text="OSINT Recon Toolkit", font=("Arial", 18, "bold"))
        title.pack(pady=10)

        tab_control = ttk.Notebook(root)

        self.username_tab = ttk.Frame(tab_control)
        self.ip_tab = ttk.Frame(tab_control)
        self.domain_tab = ttk.Frame(tab_control)
        self.metadata_tab = ttk.Frame(tab_control)

        tab_control.add(self.username_tab, text="Username Search")
        tab_control.add(self.ip_tab, text="IP Lookup")
        tab_control.add(self.domain_tab, text="Domain Info")
        tab_control.add(self.metadata_tab, text="Metadata")

        tab_control.pack(expand=1, fill="both")

        self.create_username_tab()
        self.create_ip_tab()
        self.create_domain_tab()
        self.create_metadata_tab()

    # ----------------------------
    # Username Search
    # ----------------------------

    def create_username_tab(self):
        tk.Label(self.username_tab, text="Enter Username").pack()

        self.username_entry = tk.Entry(self.username_tab, width=40)
        self.username_entry.pack(pady=5)

        tk.Button(self.username_tab, text="Search", command=self.search_username).pack()

        self.username_output = scrolledtext.ScrolledText(self.username_tab, height=20)
        self.username_output.pack(fill="both", expand=True)

    def search_username(self):

        username = self.username_entry.get()

        sites = {
            "GitHub": f"https://github.com/{username}",
            "Twitter": f"https://twitter.com/{username}",
            "Instagram": f"https://instagram.com/{username}",
            "Reddit": f"https://reddit.com/user/{username}"
        }

        self.username_output.delete(1.0, tk.END)

        for site, url in sites.items():
            try:
                r = requests.get(url)
                if r.status_code == 200:
                    self.username_output.insert(tk.END, f"[FOUND] {site}: {url}\n")
                else:
                    self.username_output.insert(tk.END, f"[NOT FOUND] {site}\n")
            except:
                pass

    # ----------------------------
    # IP Lookup
    # ----------------------------

    def create_ip_tab(self):

        tk.Label(self.ip_tab, text="Enter IP Address").pack()

        self.ip_entry = tk.Entry(self.ip_tab, width=40)
        self.ip_entry.pack(pady=5)

        tk.Button(self.ip_tab, text="Lookup", command=self.lookup_ip).pack()

        self.ip_output = scrolledtext.ScrolledText(self.ip_tab)
        self.ip_output.pack(fill="both", expand=True)

    def lookup_ip(self):

        ip = self.ip_entry.get()

        try:
            data = requests.get(f"http://ip-api.com/json/{ip}").json()

            self.ip_output.delete(1.0, tk.END)

            for key, value in data.items():
                self.ip_output.insert(tk.END, f"{key}: {value}\n")

        except Exception as e:
            self.ip_output.insert(tk.END, str(e))

    # ----------------------------
    # Domain WHOIS
    # ----------------------------

    def create_domain_tab(self):

        tk.Label(self.domain_tab, text="Enter Domain").pack()

        self.domain_entry = tk.Entry(self.domain_tab, width=40)
        self.domain_entry.pack(pady=5)

        tk.Button(self.domain_tab, text="Lookup", command=self.lookup_domain).pack()

        self.domain_output = scrolledtext.ScrolledText(self.domain_tab)
        self.domain_output.pack(fill="both", expand=True)

    def lookup_domain(self):

        domain = self.domain_entry.get()

        try:
            info = whois.whois(domain)

            self.domain_output.delete(1.0, tk.END)

            for k, v in info.items():
                self.domain_output.insert(tk.END, f"{k}: {v}\n")

        except Exception as e:
            self.domain_output.insert(tk.END, str(e))

    # ----------------------------
    # Metadata Extractor
    # ----------------------------

    def create_metadata_tab(self):

        tk.Button(self.metadata_tab, text="Select Image", command=self.extract_metadata).pack(pady=10)

        self.meta_output = scrolledtext.ScrolledText(self.metadata_tab)
        self.meta_output.pack(fill="both", expand=True)

    def extract_metadata(self):

        file_path = filedialog.askopenfilename()

        try:
            image = Image.open(file_path)
            exif = image._getexif()

            self.meta_output.delete(1.0, tk.END)

            if exif:
                for tag, value in exif.items():
                    decoded = TAGS.get(tag, tag)
                    self.meta_output.insert(tk.END, f"{decoded}: {value}\n")

            else:
                self.meta_output.insert(tk.END, "No metadata found")

        except Exception as e:
            self.meta_output.insert(tk.END, str(e))


# ----------------------------
# Run Application
# ----------------------------

if __name__ == "__main__":

    root = tk.Tk()
    app = OSINTToolkit(root)
    root.mainloop()