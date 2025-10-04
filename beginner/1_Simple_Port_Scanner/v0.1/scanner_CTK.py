# scanner_CTK.py
# Make sure 'tobproject.ico' is in the same directory as this script.

import os
import customtkinter as ctk
from tkinter import messagebox, filedialog, PhotoImage, simpledialog, Tk
import subprocess
import xml.etree.ElementTree as ET
import ipaddress
import urllib.request
import json
from datetime import datetime
import csv
import webbrowser
import threading

# Adjust PATH for nmap if necessary (Windows example)
os.environ["PATH"] += os.pathsep + r"C:\Program Files (x86)\Nmap"

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

ip_info_cache = {}

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except:
        return False

def is_valid_port(port_str):
    try:
        p = int(port_str); return 1 <= p <= 65535
    except:
        return False

def fetch_ip_info(ip):
    if not ip:
        return {'error': 'Empty IP'}
    if ip in ip_info_cache:
        return ip_info_cache[ip]
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,isp,query"
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            data = json.loads(r.read().decode('utf-8', errors='ignore'))
            if data.get('status') == 'success':
                ip_info_cache[ip] = data
                return data
            return {'error': data.get('message', 'Unknown error')}
    except Exception as e:
        return {'error': str(e)}

def format_ipinfo(info):
    if not info or 'error' in info:
        return f"Error: {info.get('error') if info else 'no info'}"
    return f"{info.get('country','')}, {info.get('regionName','')}, {info.get('city','')} (lat:{info.get('lat')}, lon:{info.get('lon')}) ISP: {info.get('isp','')}"

def parse_nmap_xml(xml_str, port_to_check):
    try:
        root = ET.fromstring(xml_str)
    except Exception as e:
        return (None, port_to_check, 'error', f'XML parse error: {e}')
    for host in root.findall('host'):
        addr_elem = host.find('address')
        addr = addr_elem.get('addr') if addr_elem is not None else None
        ports = host.find('ports')
        if ports is None:
            continue
        for p in ports.findall('port'):
            if p.get('portid') == str(port_to_check):
                state_elem = p.find('state')
                state = state_elem.get('state') if state_elem is not None else 'unknown'
                service_elem = p.find('service')
                name = service_elem.get('name','') if service_elem is not None else ''
                product = service_elem.get('product','') if service_elem is not None else ''
                version = service_elem.get('version','') if service_elem is not None else ''
                service_full = name
                if product:
                    service_full += f" ({product} {version})"
                return (addr, port_to_check, state, service_full or 'no service detected')
    return (None, port_to_check, 'unknown', 'Port not reported')

def run_nmap_with_stats(ip, port, stats_every, status_callback=None):
    cmd = ['nmap', '-sT', '-Pn', '-p', str(port), '-oX', '-']
    if stats_every:
        cmd += ['--stats-every', stats_every]
    cmd.append(ip)
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    except FileNotFoundError:
        if status_callback:
            status_callback("ERROR: nmap not found. Adjust PATH.\n")
        return (ip, port, 'error', 'nmap not found')
    try:
        while True:
            line = proc.stderr.readline()
            if line:
                if status_callback:
                    status_callback(line)
            elif proc.poll() is not None:
                break
        rem_err = proc.stderr.read()
        if rem_err and status_callback:
            status_callback(rem_err)
        xml_out = proc.stdout.read()
    except Exception as e:
        try:
            proc.wait(timeout=5)
            xml_out = proc.stdout.read() if proc.stdout else ''
        except:
            xml_out = ''
        if status_callback:
            status_callback(f"ERROR reading nmap: {e}\n")
    return parse_nmap_xml(xml_out, port)

def save_results_to_csv(results):
    root = Tk(); root.withdraw()
    file_path = filedialog.asksaveasfilename(initialdir=os.path.expanduser("~/Desktop"), defaultextension=".csv", filetypes=[("CSV files","*.csv")])
    root.destroy()
    if not file_path:
        return False
    with open(file_path, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["IP","Port","State","Service/Info","Country","Region","City","Lat","Lon","ISP","Timestamp"])
        for ip,port,est,serv,info,ts in results:
            if info and 'error' not in info:
                writer.writerow([ip,port,est,serv, info.get('country',''), info.get('regionName',''), info.get('city',''), info.get('lat',''), info.get('lon',''), info.get('isp',''), ts])
            else:
                writer.writerow([ip,port,est,serv,'','','','','','',ts])
    return True

# -------------------------
# App CTK
# -------------------------
class ScannerCTK(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Simple Port Scanner -CTK v0.1")
        self.geometry("750x750")
        self.resizable(False, False)

        # Custom icon (tobproject.ico in the same directory)
        ico_path = os.path.join(os.path.dirname(__file__), "tobproject.ico")
        if os.path.exists(ico_path):
            try:
                self.wm_iconbitmap(ico_path)  # Works on Windows
            except Exception:
                png_path = os.path.join(os.path.dirname(__file__), "tobproject.png")
                if os.path.exists(png_path):
                    img = PhotoImage(file=png_path)
                    self.iconphoto(False, img)
        else:
            print("Warning: 'tobproject.ico' not found in the directory.")

        header = ctk.CTkLabel(self, text="SIMPLE PORT SCANNER + IP Info", fg_color="#FFE490", text_color="black", anchor="center", height=50, font=("Helvetica", 16, "bold"))
        header.pack(fill="x")

        # Tabs
        self.tabs = ctk.CTkTabview(self, width=720, height=640)
        self.tabs.pack(padx=8, pady=8, expand=True, fill="both")
        self.tabs.add("Scanner"); self.tabs.add("Status"); self.tabs.add("About")

        # Scanner tab
        tab_scan = self.tabs.tab("Scanner")
        self.ip_entries = []
        self.port_entries = []
        self.check_vars = []
        for i in range(4):
            ctk.CTkLabel(tab_scan, text=f"IP {i+1}:").grid(row=i, column=0, padx=6, pady=4, sticky="w")
            ip_e = ctk.CTkEntry(tab_scan, width=220); ip_e.grid(row=i, column=1, padx=6, pady=4, sticky="w"); self.ip_entries.append(ip_e)
            ctk.CTkLabel(tab_scan, text=f"Port {i+1}:").grid(row=i, column=2, padx=6, pady=4, sticky="w")
            port_e = ctk.CTkEntry(tab_scan, width=120); port_e.grid(row=i, column=3, padx=6, pady=4, sticky="w"); self.port_entries.append(port_e)
            var = ctk.BooleanVar(value=True); chk = ctk.CTkCheckBox(tab_scan, text="Add", variable=var); chk.grid(row=i, column=4, padx=6, pady=4, sticky="w"); self.check_vars.append(var)

        self.select_all_var = ctk.BooleanVar(value=True)
        select_all_chk = ctk.CTkCheckBox(tab_scan, text="Select all", variable=self.select_all_var, command=self.on_select_all)
        select_all_chk.grid(row=4, column=0, columnspan=2, padx=6, pady=6, sticky="w")

        # Status Info dropdown
        ctk.CTkLabel(tab_scan, text="Status Info:").grid(row=5, column=0, padx=6, pady=4, sticky="w")
        self.status_option = ctk.CTkOptionMenu(tab_scan, values=["Off", "10 sec", "30 sec", "60 sec"])
        self.status_option.set("Off")
        self.status_option.grid(row=5, column=1, padx=6, pady=4, sticky="w")

        # Results textbox
        self.text_area = ctk.CTkTextbox(tab_scan, width=690, height=320); self.text_area.grid(row=6, column=0, columnspan=5, padx=6, pady=6)

        # Buttons
        btn_frame = ctk.CTkFrame(tab_scan); btn_frame.grid(row=7, column=0, columnspan=5, pady=(6,10))
        self.scan_btn = ctk.CTkButton(btn_frame, text="Scan", width=120, command=self.start_scan); self.scan_btn.pack(side="left", padx=6)
        self.info_btn = ctk.CTkButton(btn_frame, text="IP Info (row)", width=160, command=self.info_ip_prompt); self.info_btn.pack(side="left", padx=6)
        self.save_btn = ctk.CTkButton(btn_frame, text="Save CSV", width=120, command=self.save_csv_button); self.save_btn.pack(side="left", padx=6)
        self.clear_btn = ctk.CTkButton(btn_frame, text="Clear Results", width=140, command=self.clear_results); self.clear_btn.pack(side="left", padx=6)
        self.clear_cache_btn = ctk.CTkButton(btn_frame, text="Clear IP Cache", width=140, command=self.clear_cache); self.clear_cache_btn.pack(side="left", padx=6)

        # Status tab textbox
        status_tab = self.tabs.tab("Status")
        self.status_box = ctk.CTkTextbox(status_tab, width=690, height=520)
        self.status_box.pack(padx=6, pady=6, fill="both", expand=True)

        # About tab
        tab_about = self.tabs.tab("About")
        about_box = ctk.CTkTextbox(tab_about, width=690, height=520)
        about_box.pack(padx=6, pady=6, fill="both", expand=True)
        about_md = (
            "# SIMPLE PORT SCANNER v0.1\n"
            "**Author:** TOB Project (aka '0ldboy')\n"
            "**Version:** v0.1 (Beta)\n"
            "**Status:** Beta Phase – Project in development\n"
            "**License:** Educational and demonstration use only\n\n"
            "---\n\n"
            "## Contact\n"
            "LinkedIn: https://www.linkedin.com/in/andrespds/\n"
            "GitHub: https://github.com/tobproject\n"
            "Instagram: https://www.instagram.com/tob_project/\n"
        )
        about_box.insert("0.0", about_md)
        about_box.configure(state="disabled")

        # Links buttons
        link_frame = ctk.CTkFrame(tab_about); link_frame.pack(padx=6, pady=(0,6), fill="x")
        ctk.CTkButton(link_frame, text="LinkedIn", command=lambda: webbrowser.open_new_tab("https://www.linkedin.com/in/andrespds/")).pack(side="left", padx=6)
        ctk.CTkButton(link_frame, text="GitHub", command=lambda: webbrowser.open_new_tab("https://github.com/tobproject")).pack(side="left", padx=6)
        ctk.CTkButton(link_frame, text="Instagram", command=lambda: webbrowser.open_new_tab("https://www.instagram.com/tob_project/")).pack(side="left", padx=6)

        self.last_results = []

    # ---------- helpers & threads ----------
    def on_select_all(self):
        v = self.select_all_var.get()
        for var in self.check_vars:
            var.set(v)

    def append_result(self, msg):
        self.text_area.configure(state="normal")
        self.text_area.insert("end", msg)
        self.text_area.see("end")
        self.text_area.configure(state="disabled")

    def append_status(self, msg):
        self.status_box.configure(state="normal")
        self.status_box.insert("end", msg)
        self.status_box.see("end")
        self.status_box.configure(state="disabled")

    def clear_results(self):
        for e in self.ip_entries + self.port_entries:
            e.delete(0, "end")
        self.text_area.configure(state="normal")
        self.text_area.delete("0.0", "end")
        self.text_area.configure(state="disabled")
        self.status_box.configure(state="normal")
        self.status_box.delete("0.0", "end")
        self.status_box.configure(state="disabled")
        ip_info_cache.clear()
        self.last_results = []
        messagebox.showinfo("Reset", "Fields and results cleared.")

    def info_ip_prompt(self):
        root = Tk(); root.withdraw()
        try:
            val = simpledialog.askinteger("Row", "Enter row number (1-4):", parent=root, minvalue=1, maxvalue=4)
        finally:
            root.destroy()
        if not val:
            return
        idx = val - 1
        ip = self.ip_entries[idx].get().strip()
        if not ip:
            messagebox.showwarning("Empty IP", f"Row {val}: enter an IP.")
            return
        if not is_valid_ip(ip):
            messagebox.showwarning("Invalid IP", f"Row {val}: invalid IP.")
            return
        threading.Thread(target=self._fetch_info_thread, args=(ip, idx), daemon=True).start()

    def _fetch_info_thread(self, ip, idx):
        self.append_result(f"Fetching info for {ip}...\n")
        info = fetch_ip_info(ip)
        if 'error' in info:
            self.append_result(f"Row {idx+1} INFO ERROR: {info['error']}\n\n")
        else:
            self.append_result(f"Row {idx+1} INFO: {format_ipinfo(info)}\n\n")

    def save_csv_button(self):
        if not self.last_results:
            messagebox.showwarning("No results", "No results to save.")
            return
        ok = save_results_to_csv(self.last_results)
        if ok:
            messagebox.showinfo("Saved", "Results saved successfully.")

    def start_scan(self):
        ips = [e.get().strip() for e in self.ip_entries]
        ports = [e.get().strip() for e in self.port_entries]
        includes = [v.get() for v in self.check_vars]
        sel = self.status_option.get()
        stats_map = {"Off": None, "10 sec": "10s", "30 sec": "30s", "60 sec": "60s"}
        stats_str = stats_map.get(sel, None)
        threading.Thread(target=self.scan_thread, args=(ips, ports, includes, stats_str), daemon=True).start()

    def scan_thread(self, ips, ports, includes, stats_str):
        results = []
        self.append_result("Starting scan...\n\n")
        for i, (ip, port, include) in enumerate(zip(ips, ports, includes)):
            if not include:
                self.append_result(f"Row {i+1}: skipped by checkbox.\n")
                continue
            if not ip and not port:
                self.append_result(f"Row {i+1}: empty, skipping.\n\n")
                continue
            ts = datetime.utcnow().isoformat()
            if not is_valid_ip(ip):
                self.append_result(f"Row {i+1}: invalid IP '{ip}', skipping.\n\n")
                results.append((ip, port, 'invalid', 'Invalid IP', None, ts))
                continue
            if not is_valid_port(port):
                self.append_result(f"Row {i+1}: invalid Port '{port}', skipping.\n\n")
                results.append((ip, port, 'invalid', 'Invalid Port', None, ts))
                continue
            self.append_result(f"Scanning {ip}:{port}...\n")
            parsed = run_nmap_with_stats(ip, port, stats_str, status_callback=self.append_status)
            addr, p, state, service = parsed
            info = fetch_ip_info(ip)
            results.append((ip, port, state, service, info, ts))
            self.append_result(f"Result: State = {state}, Service = {service}\n")
            if info:
                self.append_result(f"  IP Info: {format_ipinfo(info)}\n")
            self.append_result("\n")
        self.last_results = results
        self.append_result("Scan finished.\n")

    def clear_cache(self):
        ip_info_cache.clear()
        messagebox.showinfo("Cache cleared", "IP cache cleared.")

if __name__ == "__main__":
    app = ScannerCTK()
    app.mainloop()
