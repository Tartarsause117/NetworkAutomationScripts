import tkinter as tk
import ttkbootstrap as ttk
from tkinter import filedialog, messagebox
from netmiko import ConnectHandler
import sys

# Function to load credentials from a text file
def load_credentials(file_path):
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
            return {
                'device_type': lines[0].strip(),
                'host': lines[1].strip(),
                'username': lines[2].strip(),
                'password': lines[3].strip()
            }
    except Exception as e:
        messagebox.showerror("Error", f"Error loading credentials: {e}")
        sys.exit()

# Function to connect to the switch, change hostname, and implement hardening checks
def connect_and_configure(credentials, new_hostname, hardening_criteria_path):
    try:
        protocol = "SSH" if credentials['device_type'] == 'cisco_ios' else "Telnet"
        log_output(f"Starting {protocol} connection...")

        # Connect to the device
        connection = ConnectHandler(
            device_type=credentials['device_type'],
            host=credentials['host'],
            username=credentials['username'],
            password=credentials['password']
        )
        log_output("Connected to the switch.")
        

        # Change the hostname
        config_commands = [f'hostname {new_hostname}']
        log_output("Sending configuration command to change hostname...")
        connection.send_config_set(config_commands)
        log_output(f"Hostname changed to {new_hostname}.")

        # Enable syslog
        syslog_config_commands = ("logging console informational")
        log_output("Enabling syslog for event logging...")
        connection.send_config_set(syslog_config_commands)
        log_output("Syslog configuration applied.")

        # Retrieve and save the running configuration
        log_output("Retrieving running configuration...")
        running_config = connection.send_command("show running-config")
        output_file = f"running_config_{new_hostname}.txt"
        with open(output_file, 'w') as file:
            file.write(running_config)
        log_output(f"Running config saved to {output_file}")

        # Compare running config with hardening criteria
        log_output("Comparing running configuration with hardening criteria...")
        with open(hardening_criteria_path, 'r') as criteria_file:
            hardening_criteria = criteria_file.readlines()
        
        # Check for each hardening criterion in the running config
        issues = []
        for criterion in hardening_criteria:
            if criterion.strip() not in running_config:
                issues.append(criterion.strip())
        
        if issues:
            log_output("Hardening issues found:\n" + "\n".join(issues))
        else:
            log_output("No hardening issues found. Configuration is compliant.")

        connection.disconnect()
        log_output("Connection closed.")

    except Exception as e:
        log_output(f"An error occurred: {e}")
        messagebox.showerror("Error", f"An error occurred: {e}")

# Function to handle the 'Start' button
def start_connection():
    try:
        protocol = protocol_var.get()
        device_type = 'cisco_ios' if protocol == 'SSH' else 'cisco_ios_telnet'

        credentials = load_credentials(cred_file_path.get())
        credentials['device_type'] = device_type

        new_hostname = hostname_entry.get()
        hardening_criteria_path = hardening_criteria_file_path.get()

        if new_hostname and hardening_criteria_path:
            connect_and_configure(credentials, new_hostname, hardening_criteria_path)
        else:
            messagebox.showwarning("Input Error", "Please enter a new hostname and select hardening criteria file.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Function to select the credentials file
def select_file():
    filename = filedialog.askopenfilename(title="Select Credentials File", filetypes=(("Text Files", "*.txt"), ("All Files", "*.*")))
    cred_file_path.set(filename)

# Function to select the hardening criteria file
def select_hardening_file():
    filename = filedialog.askopenfilename(title="Select Hardening Criteria File", filetypes=(("Text Files", "*.txt"), ("All Files", "*.*")))
    hardening_criteria_file_path.set(filename)
    # Hardening file should look like this or similar:
    #no ip http server
    #ip ssh version 2
    #no cdp run
    #no ip domain-lookup
    #logging buffered
    #ntp server
    #no ip source-route
    #banner motd
    #login local
    #exec-timeout 5 0
    #transport input ssh
    #exec-timeout 0 1

# Function to log output in the GUI
def log_output(text):
    log_box.config(state=ttk.NORMAL)
    log_box.insert(ttk.END, text + '\n')
    log_box.see(ttk.END)
    log_box.config(state=ttk.DISABLED)

# Set up the GUI
root = ttk.Window(themename="darkly")
root.title("Switch Configuration Tool")
root.geometry("550x800")

cred_file_path = ttk.StringVar()
hardening_criteria_file_path = ttk.StringVar()

# Credential file selection
ttk.Label(root, text="Credentials File:").pack(pady=5)
ttk.Entry(root, textvariable=cred_file_path, width=40).pack(pady=5)
ttk.Button(root, text="Browse", command=select_file).pack(pady=5)

# Hardening criteria file selection
ttk.Label(root, text="Hardening Criteria File:").pack(pady=5)
ttk.Entry(root, textvariable=hardening_criteria_file_path, width=40).pack(pady=5)
ttk.Button(root, text="Browse", command=select_hardening_file).pack(pady=5)

# Protocol selection (SSH or Telnet)
protocol_var = ttk.StringVar(value='SSH')
ttk.Label(root, text="Connection Protocol:").pack(pady=5)
ttk.Radiobutton(root, text="SSH", variable=protocol_var, value='SSH').pack(pady=5)
ttk.Radiobutton(root, text="Telnet", variable=protocol_var, value='Telnet').pack(pady=5)

# New hostname input
ttk.Label(root, text="New Hostname:").pack(pady=5)
hostname_entry = ttk.Entry(root, width=30)
hostname_entry.pack(pady=5)

# Log output box
log_box = ttk.Text(root, state=ttk.DISABLED, width=60, height=10)
log_box.pack(pady=10)

# Start button
ttk.Button(root, text="Start", command=start_connection).pack(pady=10)

# Start the GUI
root.mainloop()
