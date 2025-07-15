import socket, threading, subprocess, smtplib, time, random, string, os, csv, tkinter as tk
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from tkinter import filedialog, ttk, scrolledtext, messagebox
from pathlib import Path

# ──── SETTINGS ───────────────────────────────────────────
HOST, PORT = "0.0.0.0", 3333
FAKE_USERNAME, FAKE_PASSWORD = "admin", "1234"
LOG_FILE, ALERT_FILE, CSV_FILE = "honeypot_log.txt", "alert_log.txt", "honeypot_log.csv"

ENABLE_EMAIL_ALERT = True
SENDER_EMAIL   = "bhashithathennakoon727@gmail.com"
APP_PASSWORD   = "magz pxjq hhgc ylyd"
RECEIVER_EMAIL = "mininduspotify@gmail.com"
# ---------------------------------------------------------

# ──── PATIENT CSV → virtual FS loader ────────────────────
PATIENT_CSV = Path(r"C:\original honeypot\fake_patient_records_1000.csv")

def load_patient_records(csv_path=PATIENT_CSV):
    patients = {"2023": {}, "2024": {}, "2025": {}}
    if not csv_path.exists():
        print(f"[WARN] CSV '{csv_path}' not found – honeypot will have empty patient folders")
        return patients
    with csv_path.open(newline="", encoding="utf-8") as f:
        for idx, row in enumerate(csv.DictReader(f), 1):
            year = ("2023", "2024", "2025")[(idx - 1) % 3]
            fname = f"{row['Name'].replace(' ', '_')}_{row['Patient ID']}.txt"
            text = (
                f"PatientID  : {row['Patient ID']}\n"
                f"Name       : {row['Name']}\n"
                f"DOB        : {row['DOB']}\n"
                f"Condition  : {row['Condition']}\n"
                f"Heart Rate : {row['Heart Rate']}\n"
                f"BloodPress : {row['Blood Pressure']}\n"
                f"Allergies  : {row['Allergies']}\n"
                f"Last Visit : {row['Last Visit']}\n"
            )
            patients[year][fname] = text
    print(f"[INFO] Loaded {sum(len(v) for v in patients.values())} patient files from CSV")
    return patients
# ---------------------------------------------------------

# ──── RANDOM HELPERS (unchanged) ─────────────────────────
random_name = lambda: random.choice(
    ["John","Jane","Alex","Sam","Chris","Pat","Taylor","Morgan","Jordan","Casey"]
)+" "+random.choice(
    ["Smith","Johnson","Williams","Brown","Jones","Garcia","Miller","Davis","Martinez","Lee"])
rand_id  = lambda: ''.join(random.choices(string.digits, k=8))
rand_dev = lambda: f"[{datetime.now():%Y-%m-%d %H:%M:%S}] DeviceID:{rand_id()} Status:{random.choice(['OK','WARN','FAIL'])} Battery:{random.randint(20,100)}%"

# ──── VIRTUAL FILE-SYSTEM ────────────────────────────────
hospital_fs = {
    "home": {
        "admin": {
            "README.txt": "Welcome to the MedCtrl Hospital System.\n",
            "todo.txt"  : "1. Update patient records\n2. Review device logs\n3. Backup data\n"
        }
    },
    "etc": {
        "hospital.conf": "hospital_name=City General\nlocation=Metro City\nadmin=admin\n"
    },
    "var": {
        "log": {
            "device.log": "\n".join(rand_dev() for _ in range(40)),
            "access.log": "\n".join(
                f"[{datetime.now():%Y-%m-%d %H:%M:%S}] User:{random_name()} Action:Login"
                for _ in range(20))
        }
    },
    "devices": {
        "infusion_pump": {"config.cfg":"Model: IP-9000\nFirmware: v2.1.4\nStatus: OK\n"},
        "ct_scanner"   : {"config.cfg":"Model: CTX-300\nFirmware: v1.9.2\nStatus: OK\n"},
        "monitor"      : {"config.cfg":"Model: LifeMon7\nFirmware: v3.0.1\nStatus: OK\n"}
    },
    "patients": load_patient_records(),   # ← CSV data goes here
}
# (No old random for-loop!)

# ──── LOGGING & ALERT (unchanged) ────────────────────────
def log_attempt(ip, action, details):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{now},{ip},{action},{details}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f: f.write(line)
    hdr = not os.path.exists(CSV_FILE)
    with open(CSV_FILE,"a",newline='',encoding="utf-8") as f:
        w=csv.writer(f); 
        if hdr: w.writerow(["Time","IP","Action","Details"])
        w.writerow([now,ip,action,details])

def alert_owner(ip, reason=""):
    msg_txt = f"[ALERT] {datetime.now():%Y-%m-%d %H:%M:%S} | IP:{ip} | {reason}\n"
    with open(ALERT_FILE,"a") as f: f.write(msg_txt)
    print(msg_txt.strip())
    if not ENABLE_EMAIL_ALERT: return
    try:
        mail = MIMEMultipart(); mail["From"]=SENDER_EMAIL; mail["To"]=RECEIVER_EMAIL
        mail["Subject"]="🚨 Honeypot Alert"; mail.attach(MIMEText(msg_txt,"plain"))
        for fpath in (LOG_FILE,ALERT_FILE,CSV_FILE):
            if os.path.exists(fpath):
                with open(fpath,"rb") as f: part=MIMEApplication(f.read(),Name=fpath)
                part['Content-Disposition']=f'attachment; filename="{fpath}"'; mail.attach(part)
        with smtplib.SMTP("smtp.gmail.com",587) as s:
            s.starttls(); s.login(SENDER_EMAIL,APP_PASSWORD); s.send_message(mail)
    except Exception as e: print(f"[EMAIL ERROR] {e}")

def block_ip(ip):
    try:
        subprocess.run(
            ["powershell","-Command",
             f"New-NetFirewallRule -DisplayName Honeypot_Block_{ip.replace('.','_')} "
             f"-Direction Inbound -RemoteAddress {ip} -Action Block"],
            check=True, capture_output=True)
        print(f"[FIREWALL] Blocked {ip}")
    except Exception as e: print(f"[FIREWALL ERROR] {e}")

# ──── MINI SHELL (unchanged) ─────────────────────────────
def receive_line(sock):
    buf=""
    while True:
        ch=sock.recv(1)
        if not ch or ch==b'\r':
            sock.recv(1); break
        if ch in (b'\x08',b'\x7f'): buf=buf[:-1]; continue
        buf+=ch.decode(errors='ignore')
    return buf.strip()

class VirtualShell:
    def __init__(self): self.cwd="/"; self.fs=hospital_fs
    def _res(self,p):
        parts=[]
        if p.startswith("/"): parts=[]
        else: parts=[q for q in self.cwd.strip("/").split("/") if q]
        for w in p.strip("/").split("/"):
            if w in ("","."): continue
            if w=="..": parts=parts[:-1]
            else: parts.append(w)
        d=self.fs
        for w in parts:
            if isinstance(d,dict) and w in d: d=d[w]
            else: return None
        return d
    def ls(self,p=None):
        d=self._res(p) if p else self._res(self.cwd)
        if isinstance(d,dict):
            dirs=[k for k,v in d.items() if isinstance(v,dict)]
            files=[k for k,v in d.items() if not isinstance(v,dict)]
            return "  ".join(sorted(dirs)+sorted(files))
        return "Not a directory"
    def cd(self,p):
        dest=self._res(p) if p else self.fs
        if isinstance(dest,dict):
            self.cwd="/" if p in (None,"/") else os.path.normpath(os.path.join(self.cwd,p))
            return ""
        return "No such directory"
    def cat(self,f):
        d=self._res(self.cwd)
        if isinstance(d,dict) and f in d and isinstance(d[f],str): return d[f]
        return "No such file"
    def pwd(self): return self.cwd

def fake_iomt(cmd,shell):
    u=cmd.upper()
    if u=="PWD": return shell.pwd()
    if u.startswith("LS"): return shell.ls(cmd[3:].strip() or None)
    if u.startswith("CD "): return shell.cd(cmd[3:].strip())
    if u.startswith("CAT "): return shell.cat(cmd[4:].strip())
    if u=="HELP":
        return ("Commands: LS [DIR] | CD DIR | CAT FILE | PWD | EXIT\n")
    return "Command not found"

# ──── ATTACKER SESSION ──────────────────────────────────
def handle_client(sock, addr):
    ip=addr[0]
    sock.sendall(b"Username: "); user=receive_line(sock)
    sock.sendall(b"Password: "); pw=receive_line(sock)
    if (user,pw)!=(FAKE_USERNAME,FAKE_PASSWORD):
        log_attempt(ip,"LOGIN_FAIL",f"{user}/{pw}"); alert_owner(ip,"Bad pass"); block_ip(ip)
        sock.sendall(b"Login failed.\n"); sock.close(); return
    log_attempt(ip,"LOGIN_SUCCESS",user); shell=VirtualShell()
    sock.sendall(b"\nWelcome to MedCtrl v2.3\nType HELP. Type EXIT to quit.\n")
    sock.sendall(f"[MedCtrl:{shell.pwd()}] $ ".encode())

    start=time.time(); count=0
    try:
        while True:
            cmd=receive_line(sock)
            if not cmd: break
            if cmd.upper()=="EXIT": sock.sendall(b"Bye\n"); break
            log_attempt(ip,"CMD",cmd); count+=1
            resp=fake_iomt(cmd,shell)
            sock.sendall(resp.encode()+f"\n[MedCtrl:{shell.pwd()}] $ ".encode())
            if time.time()-start>120 or count>=20:
                alert_owner(ip,"Session limit"); block_ip(ip)
                sock.sendall(b"\n*** Session blocked ***\n"); break
    finally: sock.close()
# Start honeypot
def start_server():
    global SERVER_RUNNING
    SERVER_RUNNING = True
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
    except Exception:
        local_ip = "Unknown"
    print(f"[STARTED] Honeypot on port {PORT}")
    print(f"[INFO] Connect using IP: {local_ip} or 127.0.0.1 on port {PORT}")
    while SERVER_RUNNING:
        try:
            server.settimeout(1.0)  # So it checks the flag every second
            client, addr = server.accept()
            thread = threading.Thread(target=handle_client, args=(client, addr))
            thread.start()
        except socket.timeout:
            continue
    server.close()
    print("[STOPPED] Honeypot server stopped.")


class HoneypotUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Hospital Honeypot Dashboard")
        self.server_thread = None
        self.server_running = False

        # --- Modern Style and Colors ---
        style = ttk.Style()
        self.root.configure(bg="#fffbe6")
        style.theme_use("clam")
        style.configure("TNotebook", background="#fffbe6", borderwidth=0)
        style.configure("TNotebook.Tab", background="#ffe066", foreground="#6b4f1d", font=("Segoe UI", 11, "bold"), padding=[10, 5])
        style.map("TNotebook.Tab", background=[("selected", "#ffd700")])
        style.configure("TLabelframe", background="#fffbe6", borderwidth=2, relief="ridge", padding=10)
        style.configure("TLabelframe.Label", background="#fffbe6", foreground="#b8860b", font=("Segoe UI", 11, "bold"), padding=5)
        style.configure("TButton", background="#ffd700", foreground="#6b4f1d", font=("Segoe UI", 10, "bold"))
        style.map("TButton", background=[("active", "#ffe066")])
        style.configure("TLabel", background="#fffbe6", foreground="#6b4f1d", font=("Segoe UI", 10))
        style.configure("TEntry", fieldbackground="#fffbe6", background="#fffbe6")

        # Create notebook (tabbed interface)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True)

        # --- Dashboard Tab ---
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="Dashboard")

        # Email config frame (row 0)
        config_frame = ttk.LabelFrame(
            dashboard_frame,
            text="Email Settings",
            padding=10
        )
        config_frame.grid(row=0, column=0, padx=30, pady=(20, 10), sticky="ew")

        ttk.Label(config_frame, text="Sender Email:").grid(row=0, column=0, sticky="e", pady=2)
        self.sender_var = tk.StringVar(value=SENDER_EMAIL)
        ttk.Entry(config_frame, textvariable=self.sender_var, width=30).grid(row=0, column=1, pady=2)

        # App Password
        ttk.Label(config_frame, text="App Password:").grid(row=1, column=0, sticky="e", pady=2)
        self.app_pass_var = tk.StringVar(value=APP_PASSWORD)
        self.app_pass_entry = ttk.Entry(config_frame, textvariable=self.app_pass_var, width=30, show="*")
        self.app_pass_entry.grid(row=1, column=1, pady=2)

        self.show_pass = False  # Track visibility state
        self.toggle_btn = ttk.Button(config_frame, text="Show", width=6, command=self.toggle_password)
        self.toggle_btn.grid(row=1, column=2, padx=(5, 0), pady=2)

        ttk.Label(config_frame, text="Receiver Email:").grid(row=2, column=0, sticky="e", pady=2)
        self.receiver_var = tk.StringVar(value=RECEIVER_EMAIL)
        ttk.Entry(config_frame, textvariable=self.receiver_var, width=30).grid(row=2, column=1, pady=2)

        ttk.Button(config_frame, text="Apply", command=self.apply_config).grid(row=3, column=0, columnspan=3, pady=(10, 2))

        # Server control frame (row 1)
        control_frame = ttk.LabelFrame(
            dashboard_frame,
            text="Server Control",
            padding=10
        )
        control_frame.grid(row=1, column=0, padx=30, pady=(0, 20), sticky="ew")

        self.start_btn = ttk.Button(control_frame, text="Start Honeypot", command=self.start_server)
        self.start_btn.grid(row=0, column=0, padx=5, pady=2)
        self.stop_btn = ttk.Button(control_frame, text="Stop Honeypot", command=self.stop_server, state="disabled")
        self.stop_btn.grid(row=0, column=1, padx=5, pady=2)

        # Add server info label (initially empty)
        self.server_info_label = ttk.Label(control_frame, text="", foreground="blue")
        self.server_info_label.grid(row=1, column=0, columnspan=2, pady=(5, 0))

        # Server status indicator
        self.status_indicator = ttk.Label(control_frame, text="● OFF", foreground="red", font=("Segoe UI", 10, "bold"))
        self.status_indicator.grid(row=2, column=0, columnspan=2, pady=(5, 0))

        # --- Logs Tab ---
        logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(logs_frame, text="Logs")

        # Log viewer
        log_frame = ttk.LabelFrame(logs_frame, text="Honeypot Log", padding=10)
        log_frame.grid(row=0, column=0, padx=20, pady=10, sticky="nsew")
        self.log_text = scrolledtext.ScrolledText(log_frame, width=80, height=15, state="disabled",
            bg="#fff8dc", fg="#6b4f1d", font=("Consolas", 10))
        self.log_text.pack(fill="both", expand=True, pady=(0, 5))

        # Add auto-scroll button for honeypot log
        self.scroll_btn = ttk.Button(log_frame, text="Scroll to Bottom", command=self.scroll_log_to_bottom)
        self.scroll_btn.pack(anchor="e", pady=(2, 0))

        # Add export dropdown button for honeypot log
        self.export_log_btn = ttk.Menubutton(log_frame, text="EXPORT", direction="below", style="TButton")
        export_log_menu = tk.Menu(self.export_log_btn, tearoff=0)
        export_log_menu.add_command(label="Export as PDF", command=lambda: self.export_log_to_pdf(LOG_FILE, "honeypot_log.pdf"))
        export_log_menu.add_command(label="Export as CSV", command=lambda: self.export_log_to_csv(LOG_FILE, "honeypot_log.csv"))
        export_log_menu.add_command(label="Export as Both", command=lambda: self.export_log_both(LOG_FILE, "honeypot_log"))
        self.export_log_btn["menu"] = export_log_menu
        self.export_log_btn.pack(anchor="e", pady=(2, 0))

        # Alert viewer
        alert_frame = ttk.LabelFrame(logs_frame, text="Alert Log", padding=10)
        alert_frame.grid(row=1, column=0, padx=20, pady=10, sticky="nsew")
        self.alert_text = scrolledtext.ScrolledText(alert_frame, width=80, height=7, state="disabled",
            bg="#fff8dc", fg="#6b4f1d", font=("Consolas", 10))
        self.alert_text.pack(fill="both", expand=True, pady=(0, 5))

        # Add export PDF button for alert log
        self.export_alert_btn = ttk.Button(alert_frame, text="Export as PDF", command=lambda: self.export_log_to_pdf(ALERT_FILE, "alert_log.pdf"))
        self.export_alert_btn.pack(anchor="e", pady=(2, 0))

        # Set grid weights for logs tab
        logs_frame.grid_rowconfigure(0, weight=1)
        logs_frame.grid_rowconfigure(1, weight=1)
        logs_frame.grid_columnconfigure(0, weight=1)

        # Set grid weights for dashboard tab
        dashboard_frame.grid_rowconfigure(0, weight=0)
        dashboard_frame.grid_rowconfigure(1, weight=0)
        dashboard_frame.grid_columnconfigure(0, weight=1)

        # Periodic log/alert update
        self.update_logs()

        # Footer
        footer = ttk.Label(
            self.root,
            text="🐝 Created for Finals | Hospital Honeypot | 2025",
            anchor="center",
            font=("Segoe UI", 9, "italic"),
            background="#fffbe6",
            foreground="#b8860b"
        )
        footer.pack(side="bottom", fill="x", pady=(0, 4))

    def toggle_password(self):
        """Toggle password visibility."""
        if self.show_pass:
            self.app_pass_entry.config(show="*")
            self.toggle_btn.config(text="Show")
            self.show_pass = False
        else:
            self.app_pass_entry.config(show="")
            self.toggle_btn.config(text="Hide")
            self.show_pass = True

    def apply_config(self):
        global SENDER_EMAIL, APP_PASSWORD, RECEIVER_EMAIL
        SENDER_EMAIL = self.sender_var.get()
        APP_PASSWORD = self.app_pass_var.get()
        RECEIVER_EMAIL = self.receiver_var.get()
        messagebox.showinfo("Config", "Email settings updated.")

    def start_server(self):
        if not self.server_running:
            self.server_thread = threading.Thread(target=start_server, daemon=True)
            self.server_thread.start()
            self.server_running = True
            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")
            # Show IP and port
            try:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
            except Exception:
                local_ip = "Unknown"
            self.server_info_label.config(
                text=f"Server running at {local_ip}:{PORT}"
            )
            self.status_indicator.config(text="● ON", foreground="green")
            messagebox.showinfo("Honeypot", "Honeypot server started.")

    def stop_server(self):
        global SERVER_RUNNING
        if self.server_running:
            SERVER_RUNNING = False
            self.server_running = False
            self.start_btn.config(state="normal")
            self.stop_btn.config(state="disabled")
            # Hide IP and port
            self.server_info_label.config(text="")
            self.status_indicator.config(text="● OFF", foreground="red")
            messagebox.showinfo("Honeypot", "Honeypot server stopped.")

    def scroll_log_to_bottom(self):
        self.log_text.config(state="normal")
        self.log_text.see(tk.END)
        self.log_text.config(state="disabled")

    def update_logs(self):
        # Save current scroll position
        log_yview = self.log_text.yview()
        alert_yview = self.alert_text.yview()

        # Update honeypot log
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                log_content = f.read()
        except Exception:
            log_content = ""
        self.log_text.config(state="normal")
        self.log_text.delete(1.0, tk.END)
        self.log_text.insert(tk.END, log_content)
        self.log_text.config(state="disabled")
        # Restore previous scroll position
        self.log_text.yview_moveto(log_yview[0])

        # Update alert log
        try:
            with open(ALERT_FILE, "r", encoding="utf-8") as f:
                alert_content = f.read()
        except Exception:
            alert_content = ""
        self.alert_text.config(state="normal")
        self.alert_text.delete(1.0, tk.END)
        self.alert_text.insert(tk.END, alert_content)
        self.alert_text.config(state="disabled")
        self.alert_text.yview_moveto(alert_yview[0])

        self.root.after(2000, self.update_logs)  # Update every 2 seconds

    def export_log_to_pdf(self, log_file, default_pdf_name):
        # Ask user where to save
        pdf_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf")],
            initialfile=default_pdf_name
        )
        if not pdf_path:
            return
        try:
            with open(log_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
            c = canvas.Canvas(pdf_path, pagesize=letter)
            width, height = letter
            y = height - 40
            c.setFont("Courier", 10)
            for line in lines:
                if y < 40:
                    c.showPage()
                    c.setFont("Courier", 10)
                    y = height - 40
                c.drawString(40, y, line.rstrip())
                y -= 12
            c.save()
            messagebox.showinfo("Export", f"Exported to {pdf_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export PDF:\n{e}")

    def export_log_to_csv(self, log_file, default_csv_name):
        csv_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            initialfile=default_csv_name
        )
        if not csv_path:
            return
        try:
            with open(CSV_FILE, "r", encoding="utf-8") as src, open(csv_path, "w", encoding="utf-8") as dst:
                dst.write(src.read())
            messagebox.showinfo("Export", f"Exported to {csv_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export CSV:\n{e}")

    def export_log_both(self, log_file, base_name):
        self.export_log_to_pdf(log_file, base_name + ".pdf")
        self.export_log_to_csv(log_file, base_name + ".csv")

# --- Launch UI if run directly ---
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--no-ui":
        start_server()
    else:
        root = tk.Tk()
        app = HoneypotUI(root)
        root.mainloop()
