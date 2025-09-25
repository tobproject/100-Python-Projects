
## Feel free to contact me through the following profiles:

 ## [Linkedin](https://www.linkedin.com/in/andrespds/) | [GitHub](https://github.com/tobproject) | [Instagram](https://www.instagram.com/tob_project/)


---



# 🖥️ Open Port Monitor

A Python tool to monitor whether a specific port is open on a server.  
The script periodically checks the port status and alerts the user when it changes (open ↔ closed).  

This tool is useful for **network and system administrators** to ensure that critical services remain accessible.  

---

## 📌 Features
- Monitor specific ports on a server  
- Detect status changes (open or closed)  
- Send alerts when the port status changes  
- Continuous monitoring with configurable intervals  
- Optional email notifications  

---

## 📂 Project Structure
.
├── port_monitor.py # Main script
├── README.md # Project documentation
├── requirements.txt # List of dependencies
└── .gitignore # Git ignore file



---

## ⚙️ Requirements
- **Python 3.6+**  
- Basic knowledge of networking (ports, TCP/UDP, connections)  
- Access to a server or machine with ports to monitor  

---

## 📦 Libraries Used
- `socket`: Check connectivity to ports  
- `time`: Handle check intervals  
- `smtplib` + `email.mime.text`: *(optional)* send email notifications  

---

## ▶️ Usage
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/open-port-monitor.git
   cd open-port-monitor
   
 2. Run the script:
    ```bash
    python port_monitor.py
    
  
 3. Example configuration in the script:
 
    ip = "192.168.1.1"           # Server IP
    port = 80                    # Port to monitor
    recipient_email = "me@mail.com"  # Email for alerts

    monitor_port_with_email(ip, port, recipient_email, check_interval=60)
    
---

## 💡 Future Improvements

Monitor multiple ports at once

Save monitoring logs to a file

Customizable alert messages

Integrate with other notification services (Slack, Telegram, etc.)

📝 License

This project is licensed under the MIT License – feel free to use, modify, and share.


---

## 📄 `requirements.txt`

Standard library modules: socket, time, smtplib, email
No external dependencies required.

---

## 📄 `.gitignore`

Python cache/compiled files

pycache/
*.py[cod]
*.pyo
*.pyd
*.py.class

Virtual environments

venv/
env/
.venv/
.env/

IDE/project files

.vscode/
.idea/
*.sublime-project
*.sublime-workspace

OS-specific files

.DS_Store
Thumbs.db


---


