import tkinter as tk
from tkinter import messagebox, filedialog
import nmap
import csv
import os

# Añade manualmente la ruta de Nmap si no lo detecta
os.environ["PATH"] += os.pathsep + r"C:\Program Files (x86)\Nmap"

# Escanear IP y Puerto
def scan_ip_port(ip, port):
    scanner = nmap.PortScanner()
    try:
        scanner.scan(ip, str(port))
        estado = scanner[ip]['tcp'][int(port)]['state']
        servicio = scanner[ip]['tcp'][int(port)]['name']
        return (ip, port, estado, servicio)
    except Exception as e:
        return (ip, port, 'error', str(e))

# Guardar resultados a CSV
def save_results_to_csv(results, filename="scan_results.csv"):
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Dirección IP", "Puerto", "Estado", "Servicio"])
        for result in results:
            writer.writerow(result)
    print(f"Resultados guardados en {filename}")

# Función que se ejecuta al pulsar "Escanear"
def start_scan():
    results = []
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, "Iniciando escaneo...\n\n")

    for i in range(4):
        ip = ip_entries[i].get()
        port = port_entries[i].get()
        
        if ip and port:
            result_text.insert(tk.END, f"Escaneando {ip}:{port}...\n")
            result = scan_ip_port(ip, port)
            results.append(result)
            result_text.insert(tk.END, f"Resultado: Estado = {result[2]}, Servicio = {result[3]}\n\n")
        else:
            result_text.insert(tk.END, f"Fila {i+1} incompleta, omitiendo.\n\n")

    # Ventana para elegir el archivo donde guardar
    file_path = filedialog.asksaveasfilename(
        initialdir=os.path.expanduser("~\\Desktop"),  # Opcional: abrir en el Escritorio
        defaultextension=".csv",
        filetypes=[("CSV files", "*.csv")],
        title="Guardar resultados como..."
    )

    if file_path:
        save_results_to_csv(results, file_path)
        messagebox.showinfo("Éxito", f"Resultados guardados en:\n{file_path}")
    else:
        messagebox.showwarning("Cancelado", "No se guardaron los resultados.")

# Interfaz gráfica
window = tk.Tk()
window.title("Escáner de Puertos con Nmap")

ip_entries = []
port_entries = []

# Crear 4 filas de IP/Puerto
for i in range(4):
    tk.Label(window, text=f"Dirección IP {i+1}:").grid(row=i, column=0, padx=5, pady=5)
    ip_entry = tk.Entry(window)
    ip_entry.grid(row=i, column=1, padx=5, pady=5)
    ip_entries.append(ip_entry)

    tk.Label(window, text=f"Puerto {i+1}:").grid(row=i, column=2, padx=5, pady=5)
    port_entry = tk.Entry(window)
    port_entry.grid(row=i, column=3, padx=5, pady=5)
    port_entries.append(port_entry)

# Botón de escaneo
scan_button = tk.Button(window, text="Escanear", command=start_scan)
scan_button.grid(row=4, column=0, columnspan=4, pady=10)

# Área de resultados
result_text = tk.Text(window, width=70, height=15)
result_text.grid(row=5, column=0, columnspan=4, padx=10, pady=10)

window.mainloop()
