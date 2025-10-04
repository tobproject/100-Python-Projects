import os
import shutil

print("PATH:", os.getenv("PATH"))
print("Nmap encontrado en:", shutil.which("nmap"))
