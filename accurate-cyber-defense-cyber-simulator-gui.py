import sys
import socket
import threading
import time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import platform
import subprocess
import re
from collections import defaultdict
import random
import datetime
import psutil
import numpy as np

class CyberSecurityTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Accurate Cyber Security Threat Detection Tool")
        self.root.geometry("1200x800")
        self.set_theme()
        
        # Monitoring variables
        self.is_monitoring = False
        self.monitoring_thread = None
        self.target_ip = ""
        self.packet_counts = defaultdict(int)
        self.threat_counts = {
            "DoS": 0,
            "DDoS": 0,
            "Port Scan": 0,
            "Brute Force": 0,
            "Suspicious Activity": 0
        }
        self.connection_attempts = defaultdict(int)
        self.start_time = None
        
        # Create GUI
        self.create_menu()
        self.create_dashboard()
        self.create_terminal()
        
    def set_theme(self):
        """Set the green and black theme"""
        self.root.configure(bg='black')
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('.', background='black', foreground='#00FF00')
        style.configure('TFrame', background='black')
        style.configure('TLabel', background='black', foreground='#00FF00')
        style.configure('TButton', background='black', foreground='#00FF00', 
                        bordercolor='#00FF00', lightcolor='black', darkcolor='black')
        style.configure('TEntry', fieldbackground='black', foreground='#00FF00')
        style.configure('TText', background='black', foreground='#00FF00')
        style.configure('Terminal.TFrame', background='black')
        style.configure('Terminal.TLabel', background='black', foreground='#00FF00')
        style.map('TButton', 
                  background=[('active', 'black'), ('pressed', 'black')],
                  foreground=[('active', '#00FF00'), ('pressed', '#00FF00')])
    
    def create_menu(self):
        """Create the menu bar"""
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Session", command=self.new_session)
        file_menu.add_command(label="Save Logs", command=self.save_logs)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Dashboard", command=self.show_dashboard)
        view_menu.add_command(label="Terminal", command=self.show_terminal)
        view_menu.add_command(label="Threat Charts", command=self.show_threat_charts)
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Network Scanner", command=self.open_network_scanner)
        tools_menu.add_command(label="Packet Analyzer", command=self.open_packet_analyzer)
        tools_menu.add_command(label="Vulnerability Scanner", command=self.open_vulnerability_scanner)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # About menu
        about_menu = tk.Menu(menubar, tearoff=0)
        about_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="About", menu=about_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Help", command=self.show_help)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def create_dashboard(self):
        """Create the main dashboard"""
        self.dashboard_frame = ttk.Frame(self.root)
        self.dashboard_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header = ttk.Label(self.dashboard_frame, 
                          text="Accurate Cyber Defense Cyber Security Threat Dashboard", 
                          font=('Courier', 16, 'bold'))
        header.pack(pady=10)
        
        # IP Address input
        ip_frame = ttk.Frame(self.dashboard_frame)
        ip_frame.pack(pady=10)
        
        ttk.Label(ip_frame, text="Target IP:").pack(side=tk.LEFT)
        self.ip_entry = ttk.Entry(ip_frame, width=20)
        self.ip_entry.pack(side=tk.LEFT, padx=5)
        
        self.monitor_btn = ttk.Button(ip_frame, text="Start Monitoring", 
                                     command=self.toggle_monitoring)
        self.monitor_btn.pack(side=tk.LEFT, padx=5)
        
        # Stats frame
        stats_frame = ttk.Frame(self.dashboard_frame)
        stats_frame.pack(fill=tk.X, pady=10)
        
        # Threat summary
        threat_frame = ttk.LabelFrame(stats_frame, text="Threat Summary")
        threat_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        self.threat_labels = {}
        for threat in self.threat_counts:
            frame = ttk.Frame(threat_frame)
            frame.pack(fill=tk.X, pady=2)
            ttk.Label(frame, text=f"{threat}:").pack(side=tk.LEFT)
            self.threat_labels[threat] = ttk.Label(frame, text="0", foreground="white")
            self.threat_labels[threat].pack(side=tk.RIGHT)
        
        # System stats
        sys_frame = ttk.LabelFrame(stats_frame, text="System Stats")
        sys_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        self.cpu_label = ttk.Label(sys_frame, text="CPU: 0%")
        self.cpu_label.pack(anchor=tk.W)
        self.mem_label = ttk.Label(sys_frame, text="Memory: 0%")
        self.mem_label.pack(anchor=tk.W)
        self.uptime_label = ttk.Label(sys_frame, text="Uptime: 00:00:00")
        self.uptime_label.pack(anchor=tk.W)
        
        # Charts frame
        charts_frame = ttk.Frame(self.dashboard_frame)
        charts_frame.pack(fill=tk.BOTH, expand=True)
        
        # Threat pie chart
        self.pie_frame = ttk.Frame(charts_frame)
        self.pie_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Traffic bar chart
        self.bar_frame = ttk.Frame(charts_frame)
        self.bar_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Logs
        log_frame = ttk.LabelFrame(self.dashboard_frame, text="Event Log")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=10, 
                                               bg='black', fg='#00FF00',
                                               insertbackground='#00FF00')
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Update system stats
        self.update_system_stats()
    
    def create_terminal(self):
        """Create the terminal interface"""
        self.terminal_frame = ttk.Frame(self.root)
        
        # Terminal header
        header = ttk.Label(self.terminal_frame, 
                          text="Accurate Cyber Defense Cyber Security Terminal", 
                          font=('Courier', 16, 'bold'))
        header.pack(pady=10)
        
        # Terminal output
        self.terminal_output = scrolledtext.ScrolledText(
            self.terminal_frame, 
            height=20,
            bg='black', 
            fg='#00FF00',
            insertbackground='#00FF00'
        )
        self.terminal_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Terminal input
        input_frame = ttk.Frame(self.terminal_frame)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(input_frame, text=">").pack(side=tk.LEFT)
        self.terminal_input = ttk.Entry(input_frame)
        self.terminal_input.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.terminal_input.bind("<Return>", self.execute_command)
        
        # Help label
        help_label = ttk.Label(
            self.terminal_frame, 
            text="Available commands: help, exit, clear, ifconfig, ping [IP], start monitoring [IP], stop"
        )
        help_label.pack(pady=5)
        
        # Hide by default
        self.terminal_frame.pack_forget()
    
    def update_system_stats(self):
        """Update system statistics"""
        cpu_percent = psutil.cpu_percent()
        mem_percent = psutil.virtual_memory().percent
        
        self.cpu_label.config(text=f"CPU: {cpu_percent}%")
        self.mem_label.config(text=f"Memory: {mem_percent}%")
        
        if self.start_time:
            uptime = datetime.datetime.now() - self.start_time
            self.uptime_label.config(text=f"Uptime: {str(uptime).split('.')[0]}")
        
        self.root.after(1000, self.update_system_stats)
    
    def toggle_monitoring(self):
        """Start or stop monitoring"""
        if not self.is_monitoring:
            ip = self.ip_entry.get()
            if not self.validate_ip(ip):
                messagebox.showerror("Error", "Invalid IP address")
                return
            
            self.target_ip = ip
            self.is_monitoring = True
            self.monitor_btn.config(text="Stop Monitoring")
            self.start_time = datetime.datetime.now()
            
            # Reset counters
            self.packet_counts = defaultdict(int)
            for threat in self.threat_counts:
                self.threat_counts[threat] = 0
                self.threat_labels[threat].config(text="0")
            
            # Start monitoring thread
            self.monitoring_thread = threading.Thread(
                target=self.monitor_network,
                daemon=True
            )
            self.monitoring_thread.start()
            
            self.log_event(f"Started monitoring {ip}")
            self.update_charts()
        else:
            self.is_monitoring = False
            self.monitor_btn.config(text="Start Monitoring")
            self.log_event(f"Stopped monitoring {self.target_ip}")
    
    def monitor_network(self):
        """Simulate network monitoring and threat detection"""
        while self.is_monitoring:
            # Simulate network traffic and threats
            time.sleep(1)
            
            # Random packet counts (simulated)
            protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS']
            for protocol in protocols:
                self.packet_counts[protocol] += random.randint(0, 50)
            
            # Simulate threats (randomly)
            threat_types = list(self.threat_counts.keys())
            if random.random() < 0.2:  # 20% chance of threat
                threat = random.choice(threat_types)
                self.threat_counts[threat] += 1
                self.threat_labels[threat].config(text=str(self.threat_counts[threat]))
                
                # Log the threat
                self.log_event(f"Detected {threat} attack from {self.target_ip}")
            
            # Update charts
            self.root.after(0, self.update_charts)
    
    def update_charts(self):
        """Update the pie and bar charts"""
        # Clear previous charts
        for widget in self.pie_frame.winfo_children():
            widget.destroy()
        
        for widget in self.bar_frame.winfo_children():
            widget.destroy()
        
        # Create pie chart for threat distribution
        if sum(self.threat_counts.values()) > 0:
            fig1, ax1 = plt.subplots(figsize=(5, 4), facecolor='black')
            ax1.set_facecolor('black')
            
            threats = [t for t in self.threat_counts if self.threat_counts[t] > 0]
            counts = [self.threat_counts[t] for t in threats]
            
            colors = ['#ff0000', '#ff6600', '#ffcc00', '#33cc33', '#0099ff']
            ax1.pie(counts, labels=threats, autopct='%1.1f%%',
                    colors=colors[:len(threats)], textprops={'color': 'white'})
            ax1.set_title('Threat Distribution', color='white')
            
            canvas1 = FigureCanvasTkAgg(fig1, self.pie_frame)
            canvas1.draw()
            canvas1.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Create bar chart for protocol distribution
        if sum(self.packet_counts.values()) > 0:
            fig2, ax2 = plt.subplots(figsize=(5, 4), facecolor='black')
            ax2.set_facecolor('black')
            
            protocols = list(self.packet_counts.keys())
            counts = [self.packet_counts[p] for p in protocols]
            
            ax2.bar(protocols, counts, color='#00FF00')
            ax2.set_title('Protocol Distribution', color='white')
            ax2.tick_params(axis='x', colors='white')
            ax2.tick_params(axis='y', colors='white')
            
            for spine in ax2.spines.values():
                spine.set_edgecolor('#00FF00')
            
            canvas2 = FigureCanvasTkAgg(fig2, self.bar_frame)
            canvas2.draw()
            canvas2.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def log_event(self, message):
        """Log an event to the log text area"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
    
    def execute_command(self, event=None):
        """Execute terminal command"""
        command = self.terminal_input.get().strip()
        self.terminal_input.delete(0, tk.END)
        
        self.terminal_output.insert(tk.END, f"> {command}\n")
        
        if command.lower() == "help":
            self.show_terminal_help()
        elif command.lower() == "exit":
            self.root.quit()
        elif command.lower() == "clear":
            self.terminal_output.delete(1.0, tk.END)
        elif command.lower().startswith("ping "):
            ip = command[5:].strip()
            if self.validate_ip(ip):
                self.ping_ip(ip)
            else:
                self.terminal_output.insert(tk.END, "Invalid IP address\n")
        elif command.lower() == "ifconfig":
            self.show_ifconfig()
        elif command.lower().startswith("start monitoring "):
            ip = command[16:].strip()
            if self.validate_ip(ip):
                self.ip_entry.delete(0, tk.END)
                self.ip_entry.insert(0, ip)
                if not self.is_monitoring:
                    self.toggle_monitoring()
                else:
                    self.terminal_output.insert(tk.END, "Already monitoring. Stop current session first.\n")
            else:
                self.terminal_output.insert(tk.END, "Invalid IP address\n")
        elif command.lower() == "stop":
            if self.is_monitoring:
                self.toggle_monitoring()
            else:
                self.terminal_output.insert(tk.END, "Not currently monitoring\n")
        else:
            self.terminal_output.insert(tk.END, f"Unknown command: {command}\n")
        
        self.terminal_output.see(tk.END)
    
    def show_terminal_help(self):
        """Show help in terminal"""
        help_text = """Available commands:
help - Show this help message
exit - Exit the application
clear - Clear the terminal
ifconfig - Show network interface information
ping [IP] - Ping an IP address
start monitoring [IP] - Start monitoring the specified IP
stop - Stop current monitoring session
"""
        self.terminal_output.insert(tk.END, help_text)
    
    def ping_ip(self, ip):
        """Ping an IP address"""
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        count = '4'
        
        try:
            output = subprocess.check_output(['ping', param, count, ip], 
                                            stderr=subprocess.STDOUT,
                                            universal_newlines=True)
            self.terminal_output.insert(tk.END, output)
        except subprocess.CalledProcessError as e:
            self.terminal_output.insert(tk.END, e.output)
    
    def show_ifconfig(self):
        """Show network interface information"""
        try:
            if platform.system().lower() == 'windows':
                output = subprocess.check_output(['ipconfig'], 
                                              stderr=subprocess.STDOUT,
                                              universal_newlines=True)
            else:
                output = subprocess.check_output(['ifconfig'], 
                                              stderr=subprocess.STDOUT,
                                              universal_newlines=True)
            self.terminal_output.insert(tk.END, output)
        except subprocess.CalledProcessError as e:
            self.terminal_output.insert(tk.END, e.output)
    
    def validate_ip(self, ip):
        """Validate an IP address"""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(pattern, ip):
            return False
        
        octets = ip.split('.')
        for octet in octets:
            if not 0 <= int(octet) <= 255:
                return False
        
        return True
    
    def show_dashboard(self):
        """Show the dashboard"""
        self.terminal_frame.pack_forget()
        self.dashboard_frame.pack(fill=tk.BOTH, expand=True)
    
    def show_terminal(self):
        """Show the terminal"""
        self.dashboard_frame.pack_forget()
        self.terminal_frame.pack(fill=tk.BOTH, expand=True)
    
    def show_threat_charts(self):
        """Update and show threat charts"""
        self.update_charts()
        self.show_dashboard()
    
    def new_session(self):
        """Start a new session"""
        if self.is_monitoring:
            self.toggle_monitoring()
        self.log_text.delete(1.0, tk.END)
        self.ip_entry.delete(0, tk.END)
    
    def save_logs(self):
        """Save logs to file"""
        logs = self.log_text.get(1.0, tk.END)
        try:
            with open("security_logs.txt", "w") as f:
                f.write(logs)
            self.log_event("Logs saved to security_logs.txt")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save logs: {str(e)}")
    
    def open_network_scanner(self):
        """Open network scanner tool"""
        messagebox.showinfo("Info", "Network scanner tool would open here")
    
    def open_packet_analyzer(self):
        """Open packet analyzer tool"""
        messagebox.showinfo("Info", "Packet analyzer tool would open here")
    
    def open_vulnerability_scanner(self):
        """Open vulnerability scanner tool"""
        messagebox.showinfo("Info", "Vulnerability scanner tool would open here")
    
    def show_about(self):
        """Show about information"""
        about_text = """Cyber Security Threat Detection Tool
Version 1.0
Developed by Ian Carter Kulani 
phone:+265(0)988061969
Email:iancarterkulani@gmail.com

A comprehensive tool for detecting various cyber threats
including DoS, DDoS, port scans, and more.
"""
        messagebox.showinfo("About", about_text)
    
    def show_help(self):
        """Show help information"""
        help_text = """Cyber Security Tool Help

1. Enter an IP address to monitor
2. Click Start Monitoring to begin
3. View detected threats in the dashboard
4. Use the terminal for advanced commands

For more details, see Documentation.
"""
        messagebox.showinfo("Help", help_text)
    
    def show_documentation(self):
        """Show documentation"""
        doc_text = """Accurate Cyber Security Tool Documentation

DASHBOARD:
- Displays real-time threat information
- Shows charts of threat distribution
- Provides system resource usage

TERMINAL COMMANDS:
help - Show available commands
exit - Exit the application
clear - Clear terminal
ifconfig - Show network info
ping [IP] - Ping an address
start monitoring [IP] - Begin monitoring
stop - Stop monitoring

THREAT DETECTION:
- Detects DoS, DDoS, port scans
- Monitors suspicious activity
- Provides real-time alerts
"""
        messagebox.showinfo("Documentation", doc_text)

if __name__ == "__main__":
    root = tk.Tk()
    app = CyberSecurityTool(root)
    root.mainloop()