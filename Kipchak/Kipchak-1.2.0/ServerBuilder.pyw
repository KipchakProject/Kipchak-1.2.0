import tkinter as tk
from tkinter import messagebox, ttk
import subprocess
import os
import shutil


def generate_smb_server(ip, port):
    smb_code = f'''import socket
import threading

def handle_client(client_socket):
    try:
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            client_socket.send(b"\\x00\\x00\\x00\\x90" + b"FAKESMB" * 10)
    except Exception:
        pass
    finally:
        client_socket.close()

def start_server(ip="{ip}", port={port}):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((ip, port))
    server.listen(5)
    print(f"[+] Vulnerable SMB server listening on {{ip}}:{{port}}")

    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()

if __name__ == "__main__":
    start_server()
'''
    return smb_code


def show_disclaimer():
    disclaimer = tk.Toplevel(root)
    disclaimer.title("⚠️ Legal Disclaimer")
    disclaimer.geometry("520x350")
    disclaimer.configure(bg="#7B241C")

    try:
        disclaimer.iconbitmap("kip3.ico")
    except:
        pass

    disclaimer_text = (
        "⚡ Legal Disclaimer:\n\n"
        "This tool is intended ONLY for authorized penetration testing and educational purposes.\n\n"
        "Misuse is illegal. Ensure you have proper permissions.\n\n"
        "By proceeding, you accept full responsibility for your actions."
    )

    tk.Label(disclaimer, text=disclaimer_text, bg="#7B241C", fg="white",
             font=("Segoe UI", 10), wraplength=480, justify="left").pack(pady=20)

    agree_var = tk.IntVar()
    agree_check = tk.Checkbutton(disclaimer, text="I understand and agree",
                                 variable=agree_var, bg="#7B241C", fg="white",
                                 font=("Segoe UI", 10), selectcolor="#7B241C", activebackground="#7B241C")
    agree_check.pack(pady=5)

    def on_accept():
        if agree_var.get() == 1:
            disclaimer.destroy()
            create_smb_payload()
        else:
            messagebox.showwarning("Warning", "You must agree to the disclaimer to continue.")

    ttk.Button(disclaimer, text="Accept & Continue", command=on_accept).pack(pady=15)


def create_smb_payload():
    ip = ip_entry.get().strip()
    filename = filename_entry.get().strip()
    port = port_entry.get().strip()

    if not ip or not filename or not port:
        messagebox.showerror("Error", "Please fill in all fields.")
        return

    if not port.isdigit():
        messagebox.showerror("Error", "Port must be a number.")
        return

    payload = generate_smb_server(ip, int(port))

    with open("smb_payload.pyw", "w") as f:
        f.write(payload)

    messagebox.showinfo("Info", "Generating SMB server executable...")

    try:
        subprocess.run([
            "pyinstaller",
            "--onefile",
            "--noconsole",
            "--icon=Exe.ico",
            f"--name={filename}",
            "smb_payload.pyw"
        ], check=True)

        final_pyw_path = os.path.join("dist", f"{filename}.pyw")
        shutil.copy("smb_payload.pyw", final_pyw_path)

        # Cleanup
        for item in ["build", "__pycache__", "smb_payload.spec", "smb_payload.pyw"]:
            if os.path.exists(item):
                if os.path.isdir(item):
                    shutil.rmtree(item)
                else:
                    os.remove(item)

        messagebox.showinfo("Success", f"Executable + .pyw created in /dist/\n→ {filename}.exe\n→ {filename}.pyw")
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"PyInstaller failed: {e}")


# GUI setup
root = tk.Tk()
root.title("Vulnerable SMB Server Builder ⚡")
root.geometry("450x400")
root.configure(bg="#1C2833")

try:
    root.iconbitmap("kip.ico")
except:
    pass

title_label = tk.Label(root, text="SMB Server Builder", font=("Segoe UI", 16, "bold"),
                       bg="#1C2833", fg="white")
title_label.pack(pady=15)

frame = tk.Frame(root, bg="#212F3C", padx=20, pady=20, bd=5, relief="groove")
frame.pack(pady=10)

tk.Label(frame, text="Target IP:", font=("Segoe UI", 11),
         bg="#212F3C", fg="white").pack()
ip_entry = ttk.Entry(frame, font=("Segoe UI", 11), width=30)
ip_entry.pack(pady=5)

tk.Label(frame, text="Port:", font=("Segoe UI", 11),
         bg="#212F3C", fg="white").pack()
port_entry = ttk.Entry(frame, font=("Segoe UI", 11), width=30)
port_entry.pack(pady=5)

tk.Label(frame, text="Output File Name:", font=("Segoe UI", 11),
         bg="#212F3C", fg="white").pack()
filename_entry = ttk.Entry(frame, font=("Segoe UI", 11), width=30)
filename_entry.pack(pady=5)

generate_btn = ttk.Button(frame, text="Generate SMB Server", command=show_disclaimer)
generate_btn.pack(pady=15)

root.mainloop()
