import tkinter as tk
from tkinter import scrolledtext


def minimize_window():
    root.iconify()

def close_window():
    root.destroy()


def start_move(event):
    root.x = event.x
    root.y = event.y

def stop_move(event):
    root.x = None
    root.y = None

def do_move(event):
    deltax = event.x - root.x
    deltay = event.y - root.y
    x = root.winfo_x() + deltax
    y = root.winfo_y() + deltay
    root.geometry(f"+{x}+{y}")


root = tk.Tk()
root.title("")
root.geometry("700x900")
root.configure(bg="white")
root.overrideredirect(True)


top_frame = tk.Frame(root, bg="red", height=40)
top_frame.pack(fill="x")


title_label = tk.Label(top_frame, text="Thank you for Downloading Kipchak-1.2.0!", bg="red", fg="white", font=("Helvetica", 16, "bold"))
title_label.pack(side="left", padx=10)


minimize_button = tk.Button(top_frame, text="-", command=minimize_window, bg="white", fg="red", font=("Helvetica", 12, "bold"), bd=0)
minimize_button.pack(side="right", padx=5, pady=5)


top_frame.bind("<ButtonPress-1>", start_move)
top_frame.bind("<ButtonRelease-1>", stop_move)
top_frame.bind("<B1-Motion>", do_move)


content_frame = tk.Frame(root, bg="white")
content_frame.pack(fill="both", expand=True, padx=10, pady=10)


scroll_text = scrolledtext.ScrolledText(content_frame, wrap=tk.WORD, bg="white", fg="black", font=("Courier", 11), height=8)
scroll_text.insert(tk.END, """Features:
Payload generator
Listener
Backdoor (starts after reboot)
GUI
Basic cmd commands
send messages
download Exe files""")
scroll_text.configure(state="disabled")
scroll_text.pack(fill="both", expand=True)


legal_label = tk.Label(content_frame, text="Legal:", font=("Helvetica", 14, "bold"), fg="red", bg="white")
legal_label.pack(anchor="w", pady=(10, 0))

legal_text = tk.Label(content_frame, text=(
    "This software is provided for educational and research purposes only.\n"
    "Any misuse, illegal deployment or unauthorized distribution is strictly prohibited.\n"
    "The developers take no responsibility for any damage caused by improper use \n"
    "and no trojanising of the payloads is supported. \n"
    "WHATS NEW? \n" \
    "Smb server Builder and payload injector(for advanced users) + new GUI and bugs are fixed!"
), bg="white", fg="black", font=("Helvetica", 10), justify="left")
legal_text.pack(anchor="w", pady=(5, 10))


agree_text = tk.Label(content_frame, text="By using Kipchak-1.2.0 you agree with the Terms and Conditions.", bg="white", fg="black", font=("Helvetica", 10, "italic"))
agree_text.pack(anchor="w", pady=(0, 10))


ok_button = tk.Button(root, text="OK", command=close_window, bg="red", fg="white", font=("Helvetica", 12, "bold"))
ok_button.pack(pady=10)

root.mainloop()
