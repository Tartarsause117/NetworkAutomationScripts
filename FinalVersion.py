import ttkbootstrap as ttk
from ttkbootstrap.constants import * # Stringvar 
from tkinter import filedialog, messagebox
from netmiko import ConnectHandler
import difflib # Comparison for 
import json # Setting storage for the program
import os

# Reused throughout for the log box
def log_message(text):
    log_box.config(state=NORMAL) # Makes the log box temporarily able to be written to
    log_box.insert(END, text + '\n') # Writes to the log
    log_box.see(END) # Goes to the bottom of the log
    log_box.config(state=DISABLED) # Disables editing until called again

# connection function that can be reused
def connect_to_device(credentials):
    try:
        log_message("Connecting to device...")
        connection = ConnectHandler(
            device_type=credentials['device_type'],
            host=credentials['host'],
            username=credentials['username'],
            password=credentials['password']
        )
        log_message("Connected successfully!")
        return connection
    except Exception as e:
        log_message(f"Connection failed: {e}")
        messagebox.showerror("Connection Error", f"Could not connect to the device: {e}")
        return None

# Load credentials from file and warn if there are invalid credentials or the wrong format
def load_credentials(file_path):
    try:
        with open(file_path, 'r') as file:
            creds = file.readlines()
            return {
                'device_type': creds[0].strip(), # The text can then be read by itself with no extra spaces which can mess up input
                'host': creds[1].strip(),
                'username': creds[2].strip(),
                'password': creds[3].strip()
            }
    except Exception as e:
        messagebox.showerror("Error", f"Couldn't load credentials: {e}")
        return None

# Function to retrieve and save configs
def retrieve_and_save_configs(connection, hostname):
    try:
        log_message("Retrieving running config...")
        running_config = connection.send_command("show running-config")
        with open(f"running_config_{hostname}.txt", 'w') as file:
            file.write(running_config) # Writes to a new file with the hostname as part of the file name
        log_message(f"Running config saved as running_config_{hostname}.txt.")

        log_message("Retrieving startup config...")
        startup_config = connection.send_command("show startup-config")
        log_message("Configs retrieved successfully.")
        return running_config, startup_config
    except Exception as e:
        log_message(f"Failed to retrieve configs: {e}") # Incase the connection fails or some other event interrupts connection
        return None, None

# Function to change hostname
def change_hostname(connection, new_hostname):
    try:
        log_message(f"Changing hostname to {new_hostname}...")
        connection.send_config_set([f"hostname {new_hostname}"])
        log_message(f"Hostname changed to {new_hostname}.")
    except Exception as e:
        log_message(f"Failed to change hostname: {e}")

# Function to run hardening checks
def run_hardening(connection, criteria_path):
    try:
        log_message("Running hardening checks...")
        with open(criteria_path, 'r') as file:
            hardening_criteria = file.readlines()

        running_config = connection.send_command("show running-config")
        issues = [
            criteria.strip()
            for criteria in hardening_criteria
            if criteria.strip() not in running_config
        ]

        if issues:
            log_message("Hardening issues found:\n" + "\n".join(issues))
        else:
            log_message("No hardening issues found. Configuration is compliant.")
    except Exception as e:
        log_message(f"Failed to run hardening checks: {e}")

# Function to compare configurations
def compare_configs(config1, config2, label1, label2):
    diff = difflib.unified_diff(
        config1.splitlines(),
        config2.splitlines(),
        fromfile=label1,
        tofile=label2,
        lineterm=''
    )
    return '\n'.join(line for line in diff if line.startswith(('+', '-')) and not line.startswith(('+++', '---')))

# Checks for hostname and then runs hardening check
def start_hostname_hardening():
    device_credentials = load_credentials(credentials_path.get())
    if not device_credentials: # Won't load if in the wrong format 
        return

    connection = connect_to_device(device_credentials)
    if not connection: # Will exit if device is offline or not reachable or whatever reason it can't connect
        return

    # Change hostname if the checkbox is selected
    if hostname_change_var.get():
        if hostname_var.get().strip():
            change_hostname(connection, hostname_var.get())
        else:
            messagebox.showwarning("Input Error", "Please provide a hostname.")
            return

    # Run hardening checks
    run_hardening(connection, hardening_criteria_path.get())

    connection.disconnect()


# ======= Device Configuration Comparison =======
def start_config_comparison():
    device_credentials = load_credentials(credentials_path.get())
    if not device_credentials:
        return

    connection = connect_to_device(device_credentials)
    if not connection:
        return

    # Retrieve configs
    running_config, startup_config = retrieve_and_save_configs(connection, hostname_var.get())
    if not running_config or not startup_config:
        return

    # Compare configs
    diff1 = compare_configs(running_config, startup_config, "Running Config", "Startup Config")
    log_message("--- Differences Between Running and Startup Config ---")
    log_message(diff1 or "No differences found.") # Easier than adding more logic 

    connection.disconnect()


# ======= Device Configuration Functions (Loopback,OSPF,ACL,IPSec) =======

def configure_loopback_and_interface():
    device_credentials = load_credentials(credentials_path.get())
    if not device_credentials:
        return

    connection = connect_to_device(device_credentials)
    if not connection:
        return
    
    commands1 = [
        "interface loopback0",
        "ip address 10.10.10.1 255.255.255.255",
        "no shutdown",
        "interface g0/1", 
        "ip address 192.168.1.1 255.255.255.0",
        "no shutdown",
    ]
    log_message("Sending Loopback address commands to device")
    connection.send_config_set(commands1)
    log_message("Loopback address has been successfully configured")
    connection.disconnect

def configure_ospf():
    device_credentials = load_credentials(credentials_path.get())
    if not device_credentials:
        return

    connection = connect_to_device(device_credentials)
    if not connection:
        return
    
    commands2 = [
        "router ospf 1",
        "network 10.10.10.0 0.0.0.255 area 0",
        "network 192.168.56.0 0.0.0.255 area 0",
    ]
    log_message("Sending OSPF commands to device")
    connection.send_config_set(commands2)
    log_message("OSPF has been successfully configured")
    connection.disconnect

def configure_acl():
    device_credentials = load_credentials(credentials_path.get())
    if not device_credentials:
        return

    connection = connect_to_device(device_credentials)
    if not connection:
        return
    
    commands3 = [
        "ip access-list extended BLOCK_HTTP",
        "deny tcp any any eq 80", # Blocks any http connections coming through port 80
        "permit ip any any",
        "interface g0/1",
        "ip access-group BLOCK_HTTP in",
    ]
    log_message("Sending ACL commands to device")
    connection.send_config_set(commands3)
    log_message("ACL has been successfully configured (ID of BLOCK_HTTP)")
    connection.disconnect

def configure_ipsec():
    device_credentials = load_credentials(credentials_path.get())
    if not device_credentials:
        return

    connection = connect_to_device(device_credentials)
    if not connection:
        return
    
    commands4 = [
        # ISAKMP Policy setup
        "crypto isakmp policy 10",
        "encryption aes",
        "hash sha256",
        "authentication pre-share",
        "group 14",
        "lifetime 3600",
        "crypto isakmp key MYSECRETKEY address 10.0.0.2",
        # Transform set and Crypto Map
        "crypto ipsec transform-set TS1 esp-aes esp-sha-hmac",
        "crypto map MAP1 10 ipsec-isakmp",
        "set peer 192.168.56.102",
        "set transform-set TS1",
        "match address CRYPTO_ACL",
        # Access List For IPSec
        "ip access-list extended CRYPTO_ACL",
        "permit ip 10.10.10.0 0.0.0.255 192.168.56.0 0.0.0.255",
        "deny tcp any any eq 80",
        # Apply to interface Gigabit 0/1
        "interface g0/1",
        "ip address 192.168.56.104",
        "crypto map MAP1",
    ]
    log_message("Sending IPSec commands to device")
    connection.send_config_set(commands4)
    log_message("IPSec has been successfully configured")
    connection.disconnect

def config_all(): # Can initiate all 4 at once save clicking each individually
    configure_loopback_and_interface()
    configure_ospf()
    configure_acl()
    configure_ipsec()
    log_message("Finished all tasks. Loopback address, OSPF, ACL, IPSec have all been configured")

# Checks to see if basic settings for security are enabled
def run_vulnerability_scan():
    device_credentials = load_credentials(credentials_path.get())
    if not device_credentials:
        return

    connection = connect_to_device(device_credentials)
    if not connection:
        return

    # Retrieve the running config
    running_config = connection.send_command("show running-config")

    vulnerabilities = [] # List to store vulnerabilities
    
    # Check for default password
    if 'password cisco' in running_config:
        vulnerabilities.append("Weak password found: 'cisco'")

    # Check for missing SSH configuration (assumes SSH should be enabled)
    if 'ip ssh version' not in running_config:
        vulnerabilities.append("SSH is not enabled, consider enabling SSH for secure access.")

    # Check for unencrypted passwords in running config
    if 'service password-encryption' not in running_config:
        vulnerabilities.append("Password encryption is not enabled on this device.")

    # Check for missing NTP server
    if 'ntp server' not in running_config:
        vulnerabilities.append("NTP server is not configured, time synchronization may be inaccurate.")

    # Report vulnerabilities in the log
    if vulnerabilities:
        log_message("Vulnerabilities found:\n" + "\n".join(vulnerabilities)) # Has full list of found vulnerabilities
    else:
        log_message("No vulnerabilities found. Configuration appears secure.")

    connection.disconnect()


# ======= GUI Setup + Some other logic =======
app = ttk.Window(themename="darkly")
app.title("KittyConfig: The Unified Network Management Tool")
app.geometry("900x950")
app.iconbitmap('icons8-cat-64.ico')

# storage for GUI to point to (Used as it supports real time updates I think?)
credentials_path = ttk.StringVar()
hardening_criteria_path = ttk.StringVar()
hostname_var = ttk.StringVar()

ttk.Label(app, text="Credentials File:").pack(pady=5)
ttk.Entry(app, textvariable=credentials_path, width=50).pack(pady=5)
ttk.Button(app, text="Browse", command=lambda: credentials_path.set(filedialog.askopenfilename())).pack(pady=5)

# Tabbed interface
notebook = ttk.Notebook(app)
notebook.pack(fill=BOTH, expand=TRUE, padx=10, pady=10)

# Hostname & Hardening Tab
tab1 = ttk.Frame(notebook)
notebook.add(tab1, text="Hostname & Hardening")

# Hostname Change Section
hostname_change_var = ttk.BooleanVar(value=False)
ttk.Checkbutton(tab1, text="Change Hostname", variable=hostname_change_var).pack(pady=5) # Turn on or off the option
ttk.Label(tab1, text="New Hostname:").pack(pady=5)
ttk.Entry(tab1, textvariable=hostname_var, width=50).pack(pady=5)

# Hardening Criteria Section
ttk.Label(tab1, text="Hardening Criteria File:").pack(pady=5)
ttk.Entry(tab1, textvariable=hardening_criteria_path, width=50).pack(pady=5)
ttk.Button(tab1, text="Browse", command=lambda: hardening_criteria_path.set(filedialog.askopenfilename())).pack(pady=5)

# Self explanatory
ttk.Button(tab1, text="Start", command=start_hostname_hardening).pack(pady=10)


# Comparison Tab
tab2 = ttk.Frame(notebook)
notebook.add(tab2, text="Configuration Comparison")
ttk.Label(tab2, justify=CENTER,wraplength=350, text="This will compare an offline version within this programs directory, if one is found, If there is no offline configuration one will be created when the button is pressed.").pack(pady=10)
ttk.Button(tab2, text="Run Config Comparison", command=start_config_comparison).pack(pady=10)

# Device Configuration (IPSec,OPSF etc.) Tab
tab3 = ttk.Frame(notebook)
notebook.add(tab3, text="Device Configuration")
# Buttons so that they can all be configured seperately or all together
ttk.Button(tab3, text="Configure Loopback Address", command=configure_loopback_and_interface).pack(pady=10)
ttk.Button(tab3, text="Configure OSPF", command=configure_ospf).pack(pady=10)
ttk.Button(tab3, text="Configure ACL List", command=configure_acl).pack(pady=10)
ttk.Button(tab3, text="Configure IPSec", command=configure_ipsec).pack(pady=10)
ttk.Button(tab3, text="Configure All", command=config_all).pack(pady=10) # cant figure this out at the moment i need sleep

# Vulnerability Scanning for device (Something extra)
tab4 = ttk.Frame(notebook)
notebook.add(tab4, text="Vulnerability Scanning")
ttk.Button(tab4, text="Run Vulnerability Scan", command=run_vulnerability_scan).pack(pady=10)

# Log Output
log_box = ttk.ScrolledText(app, state='disabled', height=15)
log_box.pack(fill=BOTH, expand=True, padx=10, pady=10)


def create_help_tab():
    # Create a new tab for Help
    tab5 = ttk.Frame(notebook)
    notebook.add(tab5, text="Help")

    # Create a scrollable text box for help content
    help_text_box = ttk.ScrolledText(tab5, wrap=WORD, height=20, width=80)
    help_text_box.pack(padx=10, pady=10, fill=BOTH, expand=True)

    # Help content
    help_text = """
    Unified Network Management Tool - Help Guide

    1. **Credentials File**: Provide a file containing device credentials (device_type, host, username, password).
    2. **Hostname & Hardening Tab**:
        - Change Hostname: Specify a new hostname and enable the "Change Hostname" option.
        - Hardening Checks: Upload a hardening criteria file and run checks to ensure the device is secure.
    3. **Configuration Comparison Tab**:
        - Compares the current running config with the startup config or a saved offline configuration.
        - Displays the differences between them.
    4. **Device Configuration Tab**:
        - Configure Loopback: Configure a loopback interface with a specific IP address.
        - Configure OSPF: Set up OSPF routing protocol with specified networks.
        - Configure ACL: Configure an ACL to block HTTP traffic.
        - Configure IPSec: Set up IPSec for secure communication between devices.
    5. **Vulnerability Scan**: Run a vulnerability scan to check for weak passwords, missing SSH, and other common misconfigurations.
    6. **Settings**: This can be used to store youre default credentials file if needed and can also be used to set the ip range of the network you are testing.
    
    For any further questions, please refer to the developer(Me).

    My Github: https://github.com/Tartarsause117
    """
    
    help_text_box.insert("1.0", help_text)  # Insert help text into the text box
    help_text_box.config(state=DISABLED)    # Make the text box read-only

# Add the help tab to the notebook
create_help_tab()

# Path to the settings file
SETTINGS_FILE = "settings.json"

# Default settings
default_settings = {
    "default_credentials_file": "",
    "default_ip_range": "192.168.1.0/24"
}

# Load settings from file or create defaults
def load_settings():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, 'r') as file:
            return json.load(file)
    else:
        return default_settings

# Save settings to file
def save_settings(settings):
    with open(SETTINGS_FILE, 'w') as file:
        json.dump(settings, file, indent=4)

# Settings Tab Functionality
def update_settings():
    settings["default_credentials_file"] = settings_credentials_var.get()
    settings["default_ip_range"] = settings_ip_range_var.get()
    save_settings(settings)
    auto_load_default_credentials()
    messagebox.showinfo("Settings Saved", "Your settings have been updated.")

# Automatically load default credentials if specified
def auto_load_default_credentials():
    default_credentials = settings.get("default_credentials_file", "")
    if default_credentials and os.path.exists(default_credentials):
        credentials_path.set(default_credentials)
        log_message(f"Default credentials file loaded: {default_credentials}")
    else:
        log_message("No default credentials file found or file does not exist.")

# Load initial settings
settings = load_settings()
auto_load_default_credentials()

# Add Settings Tab to GUI
settings_tab = ttk.Frame(notebook)
notebook.add(settings_tab, text="Settings")

ttk.Label(settings_tab, text="Default Credentials File:").pack(pady=5)
settings_credentials_var = ttk.StringVar(value=settings.get("default_credentials_file", ""))
ttk.Entry(settings_tab, textvariable=settings_credentials_var, width=50).pack(pady=5)
ttk.Button(settings_tab, text="Browse", command=lambda: settings_credentials_var.set(filedialog.askopenfilename())).pack(pady=5)

ttk.Label(settings_tab, text="Default IP Range:").pack(pady=5)
settings_ip_range_var = ttk.StringVar(value=settings.get("default_ip_range", ""))
ttk.Entry(settings_tab, textvariable=settings_ip_range_var, width=50).pack(pady=5)

ttk.Button(settings_tab, text="Save Settings", command=update_settings).pack(pady=10)


# Start GUI
app.mainloop()
