import nmap
import tkinter as tk
from tkinter import scrolledtext, filedialog
from tkinter import ttk
import threading
from fpdf import FPDF

# Global variables to track the scanning status
scanning = False
scan_thread = None
scan_results = []

# Function to append messages to the text box for verbosity
def append_to_textbox(message):
    text_box.insert(tk.END, message + "\n")
    text_box.see(tk.END)
    root.update_idletasks()

# Function to clear the results
def clear_results():
    text_box.delete(1.0, tk.END)
    append_to_textbox("Results cleared.")

# Function to update the progress bar
def update_progress_bar(current, total):
    progress_var.set((current / total) * 100)
    root.update_idletasks()

# Function to perform the network scan
def scan_network(ip_range, ports, nmap_options):
    global scanning, scan_results
    scan_results = []
    scan_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)
    append_to_textbox(f"Starting scan for {ip_range} with options: {nmap_options}... Please wait.")

    nm = nmap.PortScanner()
    append_to_textbox("Initialized Nmap PortScanner")

    try:
        # Construct the nmap command, include '-p' only if ports are specified
        nmap_command = nmap_options
        if ports:
            nmap_command += f" -p {ports}"

        # Perform the scan with the constructed command
        nm.scan(hosts=ip_range, arguments=nmap_command)
        append_to_textbox(f"Nmap scan in progress for {ip_range}...")

        scanning = True
        all_hosts = nm.all_hosts()
        total_hosts = len(all_hosts)

        if total_hosts == 0:
            append_to_textbox(f"No hosts found in the scan range {ip_range}.")
        else:
            # Loop through all discovered hosts in the scan result
            for i, host in enumerate(all_hosts):
                if not scanning:
                    append_to_textbox("Scan stopped by user.")
                    break
                append_to_textbox(f"Scanning host: {host}")

                # Update the progress bar
                update_progress_bar(i + 1, total_hosts)

                # Check if the host is up
                if nm[host].state() == 'up':
                    hostname = nm[host]['hostnames'][0]['name'] if nm[host]['hostnames'] else 'N/A'
                    state = nm[host].state()
                    append_to_textbox(f"IP: {host}\n  Hostname: {hostname}\n  State: {state}")

                    # Store results for saving
                    result = {
                        "IP": host,
                        "Hostname": hostname,
                        "State": state,
                        "Ports": []
                    }

                    # Display all protocols and their ports
                    for proto in nm[host].all_protocols():
                        lport = nm[host][proto].keys()
                        for port in lport:
                            port_state = nm[host][proto][port]['state']
                            append_to_textbox(f"    Port: {port}/{proto}, State: {port_state}")
                            result["Ports"].append(f"{port}/{proto} - {port_state}")

                    scan_results.append(result)
                else:
                    append_to_textbox(f"Host {host} is down.")

        append_to_textbox("Nmap scan completed")

    except Exception as e:
        append_to_textbox(f"An error occurred: {str(e)}")

    finally:
        scanning = False
        stop_button.config(state=tk.DISABLED)
        scan_button.config(state=tk.NORMAL)
        progress_var.set(0)
        append_to_textbox("Network scan completed.")

# Function to save scan results to a PDF
def save_results():
    if not scan_results:
        append_to_textbox("No scan results to save.")
        return
    
    file_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
    if file_path:
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "Nmap Scan Results", 0, 1, "C")
        
        pdf.set_font("Arial", "", 12)
        for result in scan_results:
            pdf.ln(10)
            pdf.cell(0, 10, f"IP: {result['IP']}", 0, 1)
            pdf.cell(0, 10, f"Hostname: {result['Hostname']}", 0, 1)
            pdf.cell(0, 10, f"State: {result['State']}", 0, 1)
            for port in result["Ports"]:
                pdf.cell(0, 10, f"  - {port}", 0, 1)

        pdf.output(file_path)
        append_to_textbox(f"Results saved to {file_path}")

# Function to start the scan in a new thread
def start_scan():
    global scan_thread, scanning
    if scan_thread is not None and scan_thread.is_alive():
        append_to_textbox("A scan is already in progress. Please stop it before starting a new one.")
        return
    ip_range = ip_combo.get()  # Get the IP range from the combo box (editable)
    ports = port_combo.get() if port_combo.get() else custom_ports_entry.get()  # Get ports from combo or custom entry
    nmap_options = options_entry.get()  # Get the additional Nmap options from the user
    scanning = True
    scan_thread = threading.Thread(target=scan_network, args=(ip_range, ports, nmap_options))
    scan_thread.start()

# Function to stop the scan
def stop_scan():
    global scanning, scan_thread
    scanning = False
    append_to_textbox("Stopping scan...")
    if scan_thread is not None:
        scan_thread.join()  # Ensure the thread stops before continuing
        scan_thread = None
        append_to_textbox("Scan stopped successfully.")

# Function to update the options entry with the selected example
def update_options_from_example(event):
    selected_option = options_combo.get().split(" - ", 1)[0].strip()
    options_entry.delete(0, tk.END)
    options_entry.insert(0, selected_option)

    # Check if the selected option already includes '-p'
    if '-p' in selected_option:
        # Disable the ports entry if the option includes ports
        port_combo.config(state=tk.DISABLED)
        custom_ports_entry.config(state=tk.DISABLED)
    else:
        # Enable the ports entry if no ports are specified in the option
        port_combo.config(state=tk.NORMAL)
        custom_ports_entry.config(state=tk.NORMAL)

# Function to switch to light theme
def switch_to_light_theme():
    root.config(bg="white")
    text_box.config(bg="white", fg="black", insertbackground="black")
    ip_combo.config(bg="white", fg="black")
    port_combo.config(bg="white", fg="black")
    custom_ports_entry.config(bg="white", fg="black")
    options_entry.config(bg="white", fg="black")
    for button in buttons:
        button.config(bg="lightgray", fg="black")

# Function to switch to dark theme (Matrix style)
def switch_to_dark_theme():
    root.config(bg="black")
    text_box.config(bg="black", fg="green", insertbackground="green")
    ip_combo.config(bg="black", fg="green")
    port_combo.config(bg="black", fg="green")
    custom_ports_entry.config(bg="black", fg="green")
    options_entry.config(bg="black", fg="green")
    for button in buttons:
        button.config(bg="darkgreen", fg="black")

# Function to toggle between light and dark themes
def toggle_theme():
    if root.cget("bg") == "black":
        switch_to_light_theme()
    else:
        switch_to_dark_theme()

# Create the main Tkinter window
root = tk.Tk()
root.title("Network Scanner")  # Set the title of the window

# Create a scrolled text widget to display the output from the network scan
text_box = scrolledtext.ScrolledText(root, width=60, height=20)
text_box.grid(row=0, column=0, columnspan=4, padx=10, pady=10)  # Use grid layout

# Editable combo box for IP ranges
tk.Label(root, text="IP Range or Domain:").grid(row=1, column=0, sticky=tk.W, padx=10)
ip_combo = ttk.Combobox(root, width=47, values=[
    "192.168.0.0/24",  # Common private IP range
    "192.168.1.0/24",  # Common private IP range
    "10.0.0.0/24",  # Private IP range
    "172.16.0.0/24"  # Private IP range
])
ip_combo.grid(row=1, column=1, columnspan=3, padx=10, pady=5)
ip_combo.current(0)
ip_combo.config(state="normal")  # Make the combo box editable

# Combo box for popular port options
tk.Label(root, text="Popular Port Ranges:").grid(row=2, column=0, sticky=tk.W, padx=10)
port_combo = ttk.Combobox(root, width=47, values=[
    "1-1024",  # Well-known ports
    "80,443",  # Common web ports
    "22,80,443,8080",  # Common SSH and web ports
    "1-65535",  # All ports
])
port_combo.grid(row=2, column=1, columnspan=3, padx=10, pady=5)

# Entry field for custom ports to scan
tk.Label(root, text="Custom Ports (optional):").grid(row=3, column=0, sticky=tk.W, padx=10)
custom_ports_entry = tk.Entry(root, width=50)
custom_ports_entry.grid(row=3, column=1, columnspan=3, padx=10, pady=5)

# Combo box for example Nmap options
tk.Label(root, text="Example Nmap Options:").grid(row=4, column=0, sticky=tk.W, padx=10)
options_combo = ttk.Combobox(root, width=47, values=[f"{opt} - {desc}" for opt, desc in [
    ("-sS -v", "SYN scan (default), verbose output"),
    ("-sT -v", "TCP connect scan, verbose output"),
    ("-sU -v", "UDP scan, verbose output"),
    ("-sA -v", "ACK scan to determine firewall rules, verbose output"),
    ("-sP", "Ping scan, no port scan, only discover live hosts"),
    ("-sV -v", "Version detection, verbose output"),
    ("-O -v", "OS detection, verbose output"),
    ("-A -v", "Aggressive scan with OS detection and version detection"),
    ("-T4 -A -v", "Aggressive scan with faster timing"),
    ("-Pn", "Disable host discovery, scan all IPs"),
    ("-p 1-65535", "Scan all 65535 TCP ports"),
    ("-sC", "Run default scripts"),
    ("-sW", "Windows scan"),
    ("-sM", "Maimon scan"),
    ("-b", "FTP bounce scan"),
    ("-n", "No DNS resolution"),
    ("-R", "Always resolve DNS"),
    ("-D RND:10", "Randomize the IP address")
]])
options_combo.grid(row=4, column=1, columnspan=3, padx=10, pady=5)
options_combo.bind("<<ComboboxSelected>>", update_options_from_example)

# Entry field for additional Nmap options
tk.Label(root, text="Nmap Options:").grid(row=5, column=0, sticky=tk.W, padx=10)
options_entry = tk.Entry(root, width=50)
options_entry.grid(row=5, column=1, columnspan=3, padx=10, pady=5)

# Create a button widget that triggers the network scan when clicked
scan_button = tk.Button(root, text="Scan", command=start_scan)
scan_button.grid(row=6, column=0, padx=10, pady=5)

# Create a button to stop the scan
stop_button = tk.Button(root, text="Stop Scan", command=stop_scan, state=tk.DISABLED)
stop_button.grid(row=6, column=1, padx=10, pady=5)

# Create a button to save the results to a PDF
save_button = tk.Button(root, text="Save Results", command=save_results)
save_button.grid(row=6, column=2, padx=10, pady=5)

# Create a button to clear the results
clear_button = tk.Button(root, text="Clear Results", command=clear_results)
clear_button.grid(row=6, column=3, padx=10, pady=5)

# Create a button to toggle the theme
theme_button = tk.Button(root, text="Toggle Theme", command=toggle_theme)
theme_button.grid(row=7, column=0, columnspan=4, padx=10, pady=10)

# Create a progress bar
progress_var = tk.DoubleVar()
progress_bar = ttk.Progressbar(root, variable=progress_var, maximum=100)
progress_bar.grid(row=8, column=0, columnspan=4, padx=10, pady=10, sticky=tk.W + tk.E)

# Store all buttons for easy theming
buttons = [scan_button, stop_button, save_button, clear_button, theme_button]

# Start the Tkinter main loop to keep the window open and responsive
root.mainloop()
