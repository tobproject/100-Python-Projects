import socket
import time
import smtplib
from email.mime.text import MIMEText


def check_port_status(ip, port):
    """Check if a specific port is open on a given IP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Connection timeout
        sock.connect((ip, port))  # Try to connect
        sock.close()
        return True  # Port is open
    except (socket.timeout, socket.error):
        return False  # Port is closed or unreachable


def monitor_port(ip, port, check_interval=60):
    """Continuously monitor the status of a port at defined intervals."""
    last_status = None
    while True:
        current_status = check_port_status(ip, port)
        if current_status != last_status:
            if current_status:
                print(f"Alert: Port {port} on {ip} is OPEN.")
            else:
                print(f"Alert: Port {port} on {ip} is CLOSED.")
            last_status = current_status
        time.sleep(check_interval)  # Wait before next check


def send_email_alert(subject, body, recipient_email):
    """Send an email alert."""
    sender_email = "your_email@example.com"
    password = "your_password"
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = recipient_email

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender_email, password)
            server.sendmail(sender_email, recipient_email, msg.as_string())
            print("Alert email sent successfully.")
    except Exception as e:
        print(f"Error sending email: {e}")


def monitor_port_with_email(ip, port, recipient_email, check_interval=60):
    """Monitor a port and send an email alert when its state changes."""
    last_status = None
    while True:
        current_status = check_port_status(ip, port)
        if current_status != last_status:
            subject = f"Alert: Port {port} on {ip} changed"
            body = f"The port {port} on server {ip} is now {'OPEN' if current_status else 'CLOSED'}."
            send_email_alert(subject, body, recipient_email)
            last_status = current_status
        time.sleep(check_interval)


if __name__ == "__main__":
    # Example usage
    ip = "127.0.0.1"  # Replace with the target IP
    port = 80         # Replace with the port you want to monitor
    recipient_email = "recipient@example.com"  # Replace with your email
    monitor_port_with_email(ip, port, recipient_email, check_interval=30)
