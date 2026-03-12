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
        self.root.configure(bg="#1e1e2f")

        # -------------------------
        # Styles
        # -------------------------
        style = ttk.Style()
        style.theme_use("default")

        style.configure("TNotebook",
                background="#1e1e2f",
                borderwidth=0)


        style.configure("TNotebook.Tab",
                background="#2b2b3d",
                foreground="white",
                padding=(15,8),
                font=("Segoe UI", 10, "bold"))

        style.map("TNotebook.Tab",
                background=[("selected", "#4c6ef5")],
                foreground=[("selected", "white")])

        style.configure("TLabel",
                background="#1e1e2f",
                foreground="white",
                font=("Segoe UI", 11))

        style.configure("Header.TLabel",
                font=("Segoe UI", 22, "bold"),
                foreground="#4c6ef5")

        style.configure("TEntry",
                fieldbackground="#2b2b3d",
                foreground="white",
                borderwidth=1)

        style.configure("TButton",
                font=("Segoe UI", 10, "bold"),
                padding=6)
        
        
        # -------------------------
        # Header
        # -------------------------
        
        header_frame = tk.Frame(root, bg="#1e1e2f")
        header_frame.pack(pady=20)

        title = ttk.Label(header_frame, text="OSINT Recon Toolkit", style="Header.TLabel")
        title.pack(pady=10)

        tab_control = ttk.Notebook(root)
        tab_control.pack(fill="both", expand=True, padx=20, pady=10)

        self.username_tab = tk.Frame(tab_control,bg="#1e1e2f")
        self.ip_tab = tk.Frame(tab_control,bg="#1e1e2f")
        self.domain_tab = tk.Frame(tab_control,bg="#1e1e2f")
        self.metadata_tab = tk.Frame(tab_control,bg="#1e1e2f")

        tab_control.add(self.username_tab, text="Username Search")

        u_frame = tk.Frame(self.username_tab, bg="#1e1e2f")
        u_frame.pack(pady=30)


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
        u_frame = tk.Frame(self.username_tab, bg="#1e1e2f")
        u_frame.pack(pady=30)
        ttk.Label(u_frame, text="Enter Username").pack(pady=5)
        #tk.Label(self.username_tab, text="Enter Username").pack()

        self.username_entry = ttk.Entry(u_frame, width=40)
        self.username_entry.pack(pady=5)

        ttk.Button(u_frame, text="Search", command=self.search_username).pack(pady=10)

        self.username_output = scrolledtext.ScrolledText(self.username_tab, height=20)
        self.username_output.pack(fill="both", expand=True)


        u_results = tk.Text(self.username_tab,
                    bg="#2b2b3d",
                    fg="white",
                    insertbackground="white",
                    height=20,
                    borderwidth=0)
        u_results.pack(fill="both", expand=True, padx=20, pady=10)

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

        u_frame = tk.Frame(self.ip_tab, bg="#1e1e2f")
        u_frame.pack(pady=30)
        ttk.Label(u_frame, text="Enter IP Address").pack(pady=5)

        #tk.Label(self.ip_tab, text="Enter IP Address").pack()

        self.ip_entry = ttk.Entry(u_frame, width=40)
        self.ip_entry.pack(pady=5)

        # self.ip_entry = ttk.Entry(u_frame, width=40)
        # self.ip_entry.pack(pady=5)


        #tk.Button(self.ip_tab, text="Lookup", command=self.lookup_ip).pack()

        ttk.Button(u_frame, text="Search", command=self.lookup_ip).pack(pady=10)

        # self.ip_output = scrolledtext.ScrolledText(self.ip_tab)
        # self.ip_output.pack(fill="both", expand=True)


        self.ip_output = scrolledtext.ScrolledText(self.ip_tab, height=20)
        self.ip_output.pack(fill="both", expand=True)


        ip_results = tk.Text(self.ip_tab,
                     bg="#2b2b3d",
                     fg="white",
                     insertbackground="white",
                     height=20,
                     borderwidth=0)
        ip_results.pack(fill="both", expand=True, padx=20, pady=10)




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


        
        

        #tk.Label(self.domain_tab, text="Enter Domain").pack()

        u_frame = tk.Frame(self.domain_tab, bg="#1e1e2f")
        u_frame.pack(pady=30)
        ttk.Label(u_frame, text="Enter Domain").pack(pady=5)

        

        self.domain_entry = ttk.Entry(u_frame, width=40)
        self.domain_entry.pack(pady=5)

        ttk.Button(u_frame, text="Lookup", command=self.lookup_domain).pack()

        self.domain_output = scrolledtext.ScrolledText(self.domain_tab)
        self.domain_output.pack(fill="both", expand=True)



        domain_results = tk.Text(self.domain_tab,
                         bg="#2b2b3d",
                         fg="white",
                         insertbackground="white",
                         height=20,
                         borderwidth=0)
        domain_results.pack(fill="both", expand=True, padx=20, pady=10)

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

        #tk.Button(self.metadata_tab, text="Select Image", command=self.extract_metadata).pack(pady=10)

        #coppied
        m_frame = tk.Frame(self.metadata_tab, bg="#1e1e2f")
        m_frame.pack(pady=30)
        ttk.Label(m_frame, text="Upload Image File for Metadata Analysis").pack(pady=5)
        upload_button = ttk.Button(m_frame, text="Upload Image",command=self.extract_metadata)
        upload_button.pack(pady=10)

        self.meta_output = scrolledtext.ScrolledText(self.metadata_tab)
        self.meta_output.pack(fill="both", expand=True)


        metadata_results = tk.Text(self.metadata_tab,
                           bg="#2b2b3d",
                           fg="white",
                           insertbackground="white",
                           height=20,
                           borderwidth=0)
        metadata_results.pack(fill="both", expand=True, padx=20, pady=10)

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