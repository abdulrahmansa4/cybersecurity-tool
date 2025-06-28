import subprocess
import threading
import os
import re

class NmapManager:
    def __init__(self, app):
        self.app = app
        self.nmap_process = None

    def get_nmap_path(self):
        # You can update this path as needed
        default_paths = [
            r"C:\Program Files\Nmap\nmap.exe",
            r"C:\Program Files (x86)\Nmap\nmap.exe"
        ]
        for path in default_paths:
            if os.path.exists(path):
                return path
        return "nmap"  # fallback if in PATH

    def is_nmap_installed(self):
        return os.path.exists(self.get_nmap_path())

    def run_scan(self, target, args=None):
        if not self.is_nmap_installed():
            self.app.status_var.set("Nmap not found.")
            return

        if not target:
            self.app.status_var.set("No target specified.")
            return

        args = args or ["-F"]
        cmd = [self.get_nmap_path()] + args + [target]

        self.app.nmap_output.config(state="normal")
        self.app.nmap_output.delete(1.0, "end")
        self.app.nmap_output.insert("end", f"Running: {' '.join(cmd)}\n\n")
        self.app.nmap_output.config(state="disabled")

        def scan_thread():
            try:
                self.nmap_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True
                )
                for line in self.nmap_process.stdout:
                    self.app.nmap_output.config(state="normal")
                    self.app.nmap_output.insert("end", line)
                    self.app.nmap_output.config(state="disabled")
                    self.app.nmap_output.update_idletasks()
                self.nmap_process.wait()
                self.highlight_vulns()
            except Exception as e:
                self.app.status_var.set(f"Nmap error: {e}")

        threading.Thread(target=scan_thread, daemon=True).start()

    def stop_scan(self):
        if self.nmap_process and self.nmap_process.poll() is None:
            self.nmap_process.terminate()
            self.app.status_var.set("Nmap scan terminated.")

    def highlight_vulns(self):
        text_widget = self.app.nmap_output
        text_widget.config(state="normal")
        content = text_widget.get("1.0", "end")
        text_widget.tag_config("vuln", foreground="#FF1744", font=("Segoe UI", 11, "bold"))
        for line in content.splitlines():
            if "VULNERABLE" in line or "CVE-" in line:
                index = text_widget.search(line.strip(), "1.0", stopindex="end")
                if index:
                    end_idx = f"{index} lineend"
                    text_widget.tag_add("vuln", index, end_idx)
        text_widget.config(state="disabled")
