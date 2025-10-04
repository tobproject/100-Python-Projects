# scanner_PQT.py


import sys
import os
import subprocess
import xml.etree.ElementTree as ET
import ipaddress
import urllib.request
import json
from datetime import datetime
import csv
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QTextBrowser,
    QVBoxLayout, QGridLayout, QFileDialog, QTabWidget, QCheckBox, QComboBox, QMessageBox
)
from PyQt5.QtGui import QTextCursor, QIcon
from PyQt5.QtCore import Qt, QThread, pyqtSignal

# -------------------------
# Cache y utilidades
# -------------------------
ip_info_cache = {}

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except:
        return False

def is_valid_port(port_str):
    try:
        p = int(port_str)
        return 1 <= p <= 65535
    except:
        return False

def fetch_ip_info(ip):
    if not ip:
        return {'error': 'IP vacía'}
    if ip in ip_info_cache:
        return ip_info_cache[ip]
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,isp,query"
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            raw = response.read().decode('utf-8', errors='ignore')
            data = json.loads(raw)
            if data.get('status') == 'success':
                info = {
                    'country': data.get('country',''),
                    'region': data.get('regionName',''),
                    'city': data.get('city',''),
                    'lat': data.get('lat',''),
                    'lon': data.get('lon',''),
                    'isp': data.get('isp',''),
                    'query': data.get('query','')
                }
                ip_info_cache[ip] = info
                return info
            else:
                return {'error': data.get('message','Error desconocido')}
    except Exception as e:
        return {'error': str(e)}

def format_ipinfo(info):
    if not info or 'error' in info:
        return f"Error: {info.get('error') if info else 'sin info'}"
    return f"{info.get('country','')}, {info.get('region','')}, {info.get('city','')} (lat:{info.get('lat')}, lon:{info.get('lon')}) ISP: {info.get('isp','')}"

def parse_nmap_xml(xml_str, port_to_check):
    try:
        root = ET.fromstring(xml_str)
    except Exception as e:
        return (None, port_to_check, 'error', f'XML parse error: {e}')
    for host in root.findall('host'):
        addr_elem = host.find("address")
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
                return (addr, port_to_check, state, service_full or 'sin nombre detectado')
    return (None, port_to_check, 'unknown', 'Puerto no reportado')

def run_nmap_with_stats(ip, port, stats_every, status_callback=None):
    """
    Ejecuta nmap como subprocess y devuelve el parse del XML.
    status_callback(line) recibe las líneas periódicas impresas por nmap (stderr).
    """
    cmd = ['nmap', '-sT', '-Pn', '-p', str(port), '-oX', '-']
    if stats_every:
        cmd += ['--stats-every', stats_every]
    cmd.append(ip)
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    except FileNotFoundError:
        if status_callback:
            status_callback("ERROR: No se encontró 'nmap' en PATH. Instala nmap o ajusta PATH.\n")
        return (ip, port, 'error', 'nmap no encontrado')

    # Leer stderr en tiempo real (estadísticas periódicas)
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
            status_callback(f"ERROR leyendo nmap: {e}\n")
    return parse_nmap_xml(xml_out, port)

# -------------------------
# Hilo de escaneo (PyQt)
# -------------------------
class ScanThread(QThread):
    status_update = pyqtSignal(str)   # para la pestaña Status
    result_update = pyqtSignal(str)   # para la pestaña Results
    finished_scan = pyqtSignal(list)  # results list

    def __init__(self, rows, stats_every):
        super().__init__()
        self.rows = rows
        self.stats_every = stats_every

    def run(self):
        results = []
        for (ip, port, include, idx) in self.rows:
            if not include:
                self.result_update.emit(f"Fila {idx+1}: omitida por checkbox.\n")
                continue
            if not ip and not port:
                self.result_update.emit(f"Fila {idx+1}: vacía, omitiendo.\n")
                continue
            ts = datetime.utcnow().isoformat()
            if not is_valid_ip(ip) or not is_valid_port(port):
                results.append((ip, port, 'invalid', 'IP o puerto inválido', None, ts))
                self.result_update.emit(f"Fila {idx+1}: IP o puerto inválido.\n")
                continue
            self.result_update.emit(f"Escaneando {ip}:{port}...\n")
            parsed = run_nmap_with_stats(ip, port, self.stats_every, status_callback=lambda ln: self.status_update.emit(ln))
            addr, p, state, service = parsed
            info = fetch_ip_info(ip)
            results.append((ip, port, state, service, info, ts))
            self.result_update.emit(f"Resultado fila {idx+1}: Estado={state}, Servicio={service}\n")
            if info:
                self.result_update.emit(f"  IP Info: {format_ipinfo(info)}\n")
            self.result_update.emit("\n")
        self.finished_scan.emit(results)

# -------------------------
# GUI PyQt
# -------------------------
class ScannerGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Simple Port Scanner - PyQt v0.1")
        # Icono personalizado (archivo: tobproject.ico en el mismo directorio)
        ico_path = os.path.join(os.path.dirname(__file__), "tobproject.ico")
        if os.path.exists(ico_path):
            self.setWindowIcon(QIcon(ico_path))
        else:
            # si no existe, no falla: dejamos icono por defecto
            print("Aviso: 'tobproject.ico' no encontrado en el directorio. Coloca el fichero junto al script para ver el icono.")

        self.setFixedSize(750, 750)

        main_layout = QVBoxLayout()
        self.setLayout(main_layout)

        header = QLabel("SIMPLE PORT SCANNER + IP Info")
        header.setStyleSheet("background-color: #FFE490; font-weight: bold; font-size: 18px; padding: 8px;")
        header.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(header)

        tabs = QTabWidget()
        main_layout.addWidget(tabs)

        # --- TAB: Escáner
        scan_tab = QWidget()
        tabs.addTab(scan_tab, "Scanner")
        grid = QGridLayout()
        scan_tab.setLayout(grid)

        self.ip_inputs = []
        self.port_inputs = []
        self.checks = []
        for i in range(4):
            grid.addWidget(QLabel(f"IP {i+1}:"), i, 0)
            ip_e = QLineEdit(); grid.addWidget(ip_e, i, 1); self.ip_inputs.append(ip_e)
            grid.addWidget(QLabel(f"Port {i+1}:"), i, 2)
            port_e = QLineEdit(); grid.addWidget(port_e, i, 3); self.port_inputs.append(port_e)
            cb = QCheckBox("Add"); cb.setChecked(True); grid.addWidget(cb, i, 4); self.checks.append(cb)

        # Select all
        self.select_all_cb = QCheckBox("Select all"); self.select_all_cb.setChecked(True)
        self.select_all_cb.stateChanged.connect(self.on_select_all)
        grid.addWidget(self.select_all_cb, 4, 0, 1, 2)

        # Status Info dropdown
        grid.addWidget(QLabel("Status Info:"), 5, 0)
        self.status_combo = QComboBox()
        self.status_combo.addItems(["Off", "10 sec", "30 sec", "60 sec"])
        grid.addWidget(self.status_combo, 5, 1)

        # Buttons
        self.scan_btn = QPushButton("Scan"); self.scan_btn.clicked.connect(self.on_scan_clicked)
        grid.addWidget(self.scan_btn, 5, 2)
        self.clear_btn = QPushButton("Delete results"); self.clear_btn.clicked.connect(self.on_clear_clicked)
        grid.addWidget(self.clear_btn, 5, 3)
        self.save_btn = QPushButton("Save CSV"); self.save_btn.clicked.connect(self.on_save_clicked)
        grid.addWidget(self.save_btn, 5, 4)
        self.clear_cache_btn = QPushButton("Delete IP cache"); self.clear_cache_btn.clicked.connect(self.clear_cache)
        grid.addWidget(self.clear_cache_btn, 5, 5)

        # Results area (QTextBrowser)
        self.results_browser = QTextBrowser(); self.results_browser.setOpenExternalLinks(True)
        grid.addWidget(self.results_browser, 6, 0, 1, 6)

        # --- TAB: Status (nuevamente)
        status_tab = QWidget()
        tabs.addTab(status_tab, "Status")
        status_layout = QVBoxLayout(status_tab)
        self.status_browser = QTextBrowser()
        status_layout.addWidget(self.status_browser)

        # --- TAB: About
        about_tab = QWidget()
        tabs.addTab(about_tab, "About")
        about_layout = QVBoxLayout(about_tab)
        about_html = """
        <h2>Simple Port Scanner v0.1</h2>
        <p><b>Author:</b> TOB Project, a.k.a '0ldboy'</p>
        <p><b>Version:</b> v0.1 (Beta)</p>
        <p><b>Status:</b> Beta Phase – Project in development</p>
        <p><b>License:</b> Educational and demostration use only.</p>
        <hr>
        <h3>CONTACT</h3>
        <P></P>
        <a href='https://www.linkedin.com/in/andrespds/'>LinkedIn</a> |
        <a href='https://github.com/tobproject'>GitHub</a> |
        <a href='https://www.instagram.com/tob_project/'>Instagram</a>
        """
        about_browser = QTextBrowser()
        about_browser.setHtml(about_html)
        about_browser.setOpenExternalLinks(True)
        about_layout.addWidget(about_browser)

        self.last_results = []

    def on_select_all(self, state):
        checked = (state == Qt.Checked)
        for cb in self.checks:
            cb.setChecked(checked)

    def append_result(self, text):
        self.results_browser.moveCursor(QTextCursor.End)
        self.results_browser.insertPlainText(text)
        self.results_browser.moveCursor(QTextCursor.End)

    def append_status(self, text):
        self.status_browser.moveCursor(QTextCursor.End)
        self.status_browser.insertPlainText(text)
        self.status_browser.moveCursor(QTextCursor.End)

    def on_scan_clicked(self):
        sel = self.status_combo.currentText()
        stats_map = {"Off": None, "10 sec": "10s", "30 sec": "30s", "60 sec": "60s"}
        stats_str = stats_map.get(sel, None)

        rows = []
        for idx in range(4):
            ip = self.ip_inputs[idx].text().strip()
            port = self.port_inputs[idx].text().strip()
            include = self.checks[idx].isChecked()
            rows.append((ip, port, include, idx))
        self.results_browser.clear()
        self.status_browser.clear()
        self.thread = ScanThread(rows, stats_str)
        self.thread.result_update.connect(self.append_result)
        self.thread.status_update.connect(self.append_status)
        self.thread.finished_scan.connect(self.on_finished_scan)
        self.thread.start()

    def on_finished_scan(self, results):
        self.last_results = results
        self.append_result("Escaneo finalizado.\n")

    def on_clear_clicked(self):
        self.results_browser.clear()
        self.status_browser.clear()
        for e in self.ip_inputs + self.port_inputs: e.clear()
        self.last_results = []
        ip_info_cache.clear()

    def on_save_clicked(self):
        if not self.last_results:
            QMessageBox.warning(self, "Sin resultados", "No hay resultados para guardar.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Guardar CSV", "", "CSV Files (*.csv)")
        if not path:
            return
        with open(path, "w", newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["IP","Puerto","Estado","Servicio/Info","País","Región","Ciudad","Lat","Lon","ISP","Timestamp"])
            for r in self.last_results:
                ip, port, estado, servicio, info, ts = r
                if info and isinstance(info, dict) and 'error' not in info:
                    writer.writerow([ip, port, estado, servicio, info.get('country',''), info.get('region',''), info.get('city',''), info.get('lat',''), info.get('lon',''), info.get('isp',''), ts])
                else:
                    writer.writerow([ip, port, estado, servicio, '', '', '', '', '', '', ts])
        QMessageBox.information(self, "Guardado", "CSV guardado correctamente.")

    def clear_cache(self):
        ip_info_cache.clear()
        QMessageBox.information(self, "Cache limpiada", "Cache de IPs borrada.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    gui = ScannerGUI()
    gui.show()
    sys.exit(app.exec_())
