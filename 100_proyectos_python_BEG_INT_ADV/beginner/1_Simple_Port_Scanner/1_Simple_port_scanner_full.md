
## Feel free to contact me through the following profiles:

 ## [Linkedin](https://www.linkedin.com/in/andrespds/) | [GitHub](https://github.com/tobproject) | [Instagram](https://www.instagram.com/tob_project/)










# 1: Basic Port Scanner in Python

## Description
This project consists of developing a simple Python script to perform a port scan on a host or network. The goal is to check whether the common ports of a system are open and therefore determine if there are vulnerable services accessible from the network.

---

## Project Objectives
- Learn how to work with sockets in Python to create a connection over a network.  
- Introduce the concept of port scanning as part of network security.  
- Practice the use of threads to scan multiple ports simultaneously.  
- Identify open ports in a system or network and detect potential vulnerabilities.  

---

## Requirements
1. Python 3.x  
2. Internet access or a local network to scan  
3. Basic knowledge of Python (functions, exception handling, module import)  
4. Basic networking concepts (IP, ports, TCP/UDP)  

---

## Project Development

### 1. Import required modules

```python
import socket
import threading
```

### 2. Define the function to check if a port is open

```python
def scan_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)  # Set 1-second timeout
    
    result = sock.connect_ex((ip, port))
    if result == 0:
        print(f"Port {port} is OPEN")
    sock.close()
```

### 3. Define a function to start the port scan

```python
def scan_ports(ip, ports):
    threads = []
    for port in ports:
        t = threading.Thread(target=scan_port, args=(ip, port))
        threads.append(t)
        t.start()  # Start the thread for each port
    
    for t in threads:
        t.join()  # Wait for all threads to finish
```

### 4. Request IP and ports from the user

```python
if __name__ == "__main__":
    target_ip = input("Enter the host IP address to scan: ")
    ports_to_scan = [21, 22, 23, 80, 443, 3306, 8080]  # Common ports
    print(f"Scanning ports of {target_ip}...")
    scan_ports(target_ip, ports_to_scan)
```

---

## Code Explanation
1. **Socket connection**: The `socket` module is used to establish TCP connections between the script and the target port.  
2. **Threads**: The `threading` library makes the port scanning much faster by allowing multiple ports to be scanned in parallel.  
3. **Port connection**: The function `sock.connect_ex()` attempts to connect to the target port. If successful, it returns `0`, meaning the port is open.  
4. **Simultaneous scanning**: Using threads leverages multi-core systems and greatly reduces execution time.  

---

## Future Improvements
- UDP port scanning  
- More detailed results (service detection)  
- User Interface (UI) with Tkinter or PyQt  
- Port range support  

---

## Expanded Features

### 1. Dynamic Port Range Scanning

```python
def scan_ports_range(ip, start_port, end_port):
    threads = []
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(ip, port))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()

if __name__ == "__main__":
    target_ip = input("Enter the host IP address to scan: ")
    start_port = int(input("Enter the starting port: "))
    end_port = int(input("Enter the ending port: "))
    
    print(f"Scanning {target_ip} ports from {start_port} to {end_port}...")
    scan_ports_range(target_ip, start_port, end_port)
```

### 2. Service Detection on Open Ports

```python
def detect_service(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        sock.connect((ip, port))
        sock.send(b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n')
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        
        if "HTTP" in response:
            print(f"Port {port} is OPEN - Service: HTTP")
        sock.close()
    except Exception as e:
        print(f"Error detecting service on port {port}: {e}")
```

### 3. Basic GUI with Tkinter

```python
import tkinter as tk

def start_scan():
    target_ip = ip_entry.get()
    start_port = int(start_port_entry.get())
    end_port = int(end_port_entry.get())
    
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, f"Scanning {target_ip} ports {start_port}-{end_port}...\n")
    
    scan_ports_range(target_ip, start_port, end_port)

window = tk.Tk()
window.title("Basic Port Scanner")

tk.Label(window, text="IP Address:").grid(row=0, column=0)
ip_entry = tk.Entry(window)
ip_entry.grid(row=0, column=1)

tk.Label(window, text="Start Port:").grid(row=1, column=0)
start_port_entry = tk.Entry(window)
start_port_entry.grid(row=1, column=1)

tk.Label(window, text="End Port:").grid(row=2, column=0)
end_port_entry = tk.Entry(window)
end_port_entry.grid(row=2, column=1)

scan_button = tk.Button(window, text="Scan", command=start_scan)
scan_button.grid(row=3, column=0, columnspan=2)

result_text = tk.Text(window, width=50, height=15)
result_text.grid(row=4, column=0, columnspan=2)

window.mainloop()
```

### 4. Save Results in CSV

```python
import csv

def save_results_to_csv(results, filename="scan_results.csv"):
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Port", "Status", "Service"])
        for result in results:
            writer.writerow(result)
    print(f"Results saved to {filename}")
```

### 5. UDP Port Scanning

```python
def scan_udp_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    socket.setdefaulttimeout(1)
    
    try:
        sock.sendto(b'', (ip, port))
        sock.recvfrom(1024)
        print(f"UDP Port {port} is OPEN")
    except socket.timeout:
        print(f"UDP Port {port} is CLOSED or not responding")
    finally:
        sock.close()
```

---

## Final Thoughts
This project starts as a **basic Python port scanner** and evolves into a **powerful tool** with additional features like service detection, UDP scanning, GUI, CSV export, and more. It is an excellent learning project for anyone interested in **cybersecurity and network auditing**.
