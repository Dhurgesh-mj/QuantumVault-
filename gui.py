import tkinter as tk
from tkinter import filedialog, messagebox
import threading
from Main import generate_rsa_key, secure_transfer, secure_receive
import platform

is_mac = platform.system() == "Darwin"

BG_COLOR = "#2C3E50"  # Dark blue-gray
BTN_COLOR = "#3498DB" if not is_mac else "#2E86C1"  # Deep Blue for macOS
HOVER_COLOR = "#2980B9" if not is_mac else "#1B4F72"  # Dark Navy for macOS
TEXT_COLOR = "#ECF0F1" if not is_mac else "#000000"

root = tk.Tk()
root.title("QuantumVault - Secure File Transfer")
root.geometry("400x350")
root.configure(bg=BG_COLOR)

def on_enter(e):
    e.widget["background"] = HOVER_COLOR

def on_leave(e):
    e.widget["background"] = BTN_COLOR

def styled_button(parent, text, command):
    btn = tk.Button(parent, text=text, command=command, width=25, height=2, bg=BTN_COLOR, fg=TEXT_COLOR, relief="flat", font=("Arial", 10, "bold"))
    btn.bind("<Enter>", on_enter)
    btn.bind("<Leave>", on_leave)
    btn.pack(pady=10)
    return btn

def clear_window():
    """Clears the current window contents."""
    for widget in root.winfo_children():
        widget.destroy()

def show_main_menu():
    """Displays the main menu with available options."""
    clear_window()
    
    tk.Label(root, text="SecVault - Secure Transfer", font=("Arial", 14, "bold"), bg=BG_COLOR, fg=TEXT_COLOR).pack(pady=20)
    styled_button(root, "Send File", send_file_ui)
    styled_button(root, "Receive File & Generate Keys", receive_file_ui)
    styled_button(root, "Exit", root.quit)

def send_file_ui():
    """UI for sending a secure file."""
    clear_window()
    
    tk.Label(root, text="Send Secure File", font=("Arial", 12), bg=BG_COLOR, fg=TEXT_COLOR).pack(pady=10)
    
    tk.Label(root, text="Server IP:", bg=BG_COLOR, fg=TEXT_COLOR).pack()
    server_ip_entry = tk.Entry(root)
    server_ip_entry.pack()
    
    tk.Label(root, text="Server Port:", bg=BG_COLOR, fg=TEXT_COLOR).pack()
    server_port_entry = tk.Entry(root)
    server_port_entry.pack()
    
    def select_file():
        """Allows user to select a file and starts sending it in a new thread."""
        file_path = filedialog.askopenfilename()
        if file_path:
            threading.Thread(target=send_file, args=(server_ip_entry.get(), server_port_entry.get(), file_path), daemon=True).start()
    
    styled_button(root, "Choose File & Send", select_file)
    styled_button(root, "Back", show_main_menu)

def send_file(server_ip, server_port, file_path):
    """Handles file sending and auto-returns to the main menu."""
    if not server_ip or not server_port:
        messagebox.showerror("Error", "Please enter server IP and port!")
        return
    try:
        secure_transfer(server_ip, int(server_port), file_path)
        messagebox.showinfo("Success", "File sent successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))
    root.after(1000, show_main_menu)

def receive_file_ui():
    """UI for receiving a secure file & generating keys."""
    clear_window()
    
    tk.Label(root, text="Receive Secure File & Generate Keys", font=("Arial", 12), bg=BG_COLOR, fg=TEXT_COLOR).pack(pady=10)
    
    def generate_keys():
        """Generates RSA keys."""
        generate_rsa_key("keys")
        messagebox.showinfo("Success", "RSA Keys Generated Successfully!")
    
    styled_button(root, "Generate Keys", generate_keys)
    
    tk.Label(root, text="Listening Port:", bg=BG_COLOR, fg=TEXT_COLOR).pack()
    server_port_entry = tk.Entry(root)
    server_port_entry.pack()
    
    def start_receiving():
        """Starts file receiving in a new thread."""
        port = server_port_entry.get()
        if not port:
            messagebox.showerror("Error", "Please enter a port!")
            return
        threading.Thread(target=receive_file, args=(int(port),), daemon=True).start()
    
    styled_button(root, "Start Receiving", start_receiving)
    styled_button(root, "Back", show_main_menu)

def receive_file(port):
    """Handles file receiving and auto-returns to the main menu."""
    try:
        secure_receive(port, "keys")
        messagebox.showinfo("Success", "File received successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))
    root.after(1000, show_main_menu)

# Start the GUI
def runner():
    show_main_menu()
    root.mainloop()

if __name__ =="__main__":
    runner()