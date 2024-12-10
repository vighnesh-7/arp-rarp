import tkinter as tk
from tkinter import messagebox
import random
import string
import re

class ARPCache:
    def __init__(self):
        self.ip_to_mac = {}
        self.mac_to_ip = {}

    def query_ip_to_mac(self, ip):
        if ip not in self.ip_to_mac:
            self.ip_to_mac[ip] = self.generate_mac()
            self.mac_to_ip[self.ip_to_mac[ip]] = ip
        return self.ip_to_mac[ip]

    def query_mac_to_ip(self, mac):
        if mac not in self.mac_to_ip:
            self.mac_to_ip[mac] = self.generate_ip()
            self.ip_to_mac[self.mac_to_ip[mac]] = mac
        return self.mac_to_ip[mac]

    def generate_ip(self):
        return f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}"

    def generate_mac(self):
        return ':'.join([''.join(random.choices(string.hexdigits, k=2)).upper() for _ in range(6)])

    def is_valid_ip(self, ip):
        pattern = re.compile(r'^192\.168\.\d{1,3}\.\d{1,3}$')
        return bool(pattern.match(ip)) and all(0 <= int(octet) <= 255 for octet in ip.split('.')[2:])

    def is_valid_mac(self, mac):
        pattern = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
        return bool(pattern.match(mac))


class ARPApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ARP / RARP Simulation")
        self.root.geometry("600x450")
        self.root.config(bg="#1e1e2f")

        self.arp_cache = ARPCache()

        # Title Label
        title_label = tk.Label(
            self.root, text="ARP / RARP Simulation", font=("Helvetica", 18, "bold"), bg="#1e1e2f", fg="#00d4ff"
        )
        title_label.pack(pady=10)

        # Create two frames for ARP and RARP
        main_frame = tk.Frame(self.root, bg="#1e1e2f")
        main_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        arp_frame = tk.Frame(main_frame, bg="#2e2e42", padx=20, pady=20)
        arp_frame.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=5)

        rarp_frame = tk.Frame(main_frame, bg="#2e2e42", padx=20, pady=20)
        rarp_frame.pack(side=tk.RIGHT, expand=True, fill=tk.BOTH, padx=5)

        # ARP Section
        arp_heading = tk.Label(
            arp_frame, text="ARP: IP to MAC Mapping", font=("Arial", 14, "bold"), bg="#2e2e42", fg="#ff5722"  # Orange color
        )
        arp_heading.pack(pady=10)

        ip_label = tk.Label(
            arp_frame, text="Enter IP Address (e.g., 192.168.0.1):", font=("Arial", 12), bg="#2e2e42", fg="#cccccc"
        )
        ip_label.pack(pady=5, anchor="w")

        self.ip_entry = tk.Entry(arp_frame, font=("Arial", 12), bg="#3e3e56", fg="#ffffff", insertbackground="white")
        self.ip_entry.pack(pady=10, fill=tk.X)

        self.query_ip_button = tk.Button(
            arp_frame,
            text="Query IP to MAC",
            font=("Arial", 12, "bold"),
            bg="#4caf50",  # Green button
            fg="#ffffff",
            activebackground="#388e3c",  # Darker green when active
            command=self.query_ip_to_mac,
        )
        self.query_ip_button.pack(pady=10)

        self.ip_result_label = tk.Label(
            arp_frame, text="MAC Address: ", font=("Arial", 12), bg="#2e2e42", fg="#ffffff"
        )
        self.ip_result_label.pack(pady=10)

        # RARP Section
        rarp_heading = tk.Label(
            rarp_frame, text="RARP: MAC to IP Mapping", font=("Arial", 14, "bold"), bg="#2e2e42", fg="#ff9800"  # Yellow-Orange color
        )
        rarp_heading.pack(pady=10)

        mac_label = tk.Label(
            rarp_frame, text="Enter MAC Address (e.g., 00:1A:2B:3C:4D:5E):", font=("Arial", 12), bg="#2e2e42", fg="#cccccc"
        )
        mac_label.pack(pady=5, anchor="w")

        self.mac_entry = tk.Entry(rarp_frame, font=("Arial", 12), bg="#3e3e56", fg="#ffffff", insertbackground="white")
        self.mac_entry.pack(pady=10, fill=tk.X)

        self.query_mac_button = tk.Button(
            rarp_frame,
            text="Query MAC to IP",
            font=("Arial", 12, "bold"),
            bg="#2196f3",  # Blue button
            fg="#ffffff",
            activebackground="#1976d2",  # Darker blue when active
            command=self.query_mac_to_ip,
        )
        self.query_mac_button.pack(pady=10)

        self.mac_result_label = tk.Label(
            rarp_frame, text="IP Address: ", font=("Arial", 12), bg="#2e2e42", fg="#ffffff"
        )
        self.mac_result_label.pack(pady=10)

    def query_ip_to_mac(self):
        ip = self.ip_entry.get()
        if self.arp_cache.is_valid_ip(ip):
            mac = self.arp_cache.query_ip_to_mac(ip)
            self.ip_result_label.config(text=f"MAC Address: {mac}")
        else:
            messagebox.showerror(
                "Invalid IP", "Invalid IP address format. Please enter a valid IP address in the format 192.168.x.x."
            )

    def query_mac_to_ip(self):
        mac = self.mac_entry.get()
        if self.arp_cache.is_valid_mac(mac):
            ip = self.arp_cache.query_mac_to_ip(mac)
            self.mac_result_label.config(text=f"IP Address: {ip}")
        else:
            messagebox.showerror(
                "Invalid MAC", "Invalid MAC address format. Please enter a valid MAC address in the format XX:XX:XX:XX:XX:XX."
            )


if __name__ == "__main__":
    root = tk.Tk()
    app = ARPApp(root)
    root.mainloop()
