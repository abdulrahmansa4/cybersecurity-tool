# core/capture.py
import subprocess
import threading
import re
import queue
from ttkbootstrap.dialogs import Messagebox


class TSharkManager:
    def __init__(self, app):
        self.app = app
        self.is_capturing = False
        self.capture_process = None
        self.packet_queue = queue.Queue()
        self.interface = None
        self.app.root.after(100, self.process_packet_queue)

    def refresh_interfaces(self):
        try:
            result = subprocess.run(
                ["C:\\Program Files\\Wireshark\\tshark.exe", "-D"],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            if result.returncode != 0:
                Messagebox.show_error("Error", "Could not list interfaces. Is Wireshark installed?")
                return
            interfaces = []
            self.interface_map = {}
            for line in result.stdout.splitlines():
                if match := re.match(r"\d+\. ([^ ]+) \((.+)\)", line):
                    device = match.group(1)
                    friendly = match.group(2)
                    display = f"{friendly} [{device}]"
                    interfaces.append(display)
                    self.interface_map[display] = device
            self.app.interface_combo["values"] = interfaces
            if interfaces:
                self.app.interface_combo.current(0)
        except Exception as e:
            Messagebox.show_error("Error", f"Failed to get interfaces: {str(e)}")

    def start_capture(self):
        if self.is_capturing:
            return
        interface = self.app.interface_combo.get()
        if not interface:
            Messagebox.show_error("Error", "Please select a network interface")
            return
        self.interface = self.interface_map[interface]
        self.is_capturing = True
        self.app.start_btn.config(text="Capturing...")
        threading.Thread(target=self.run_tshark_capture, daemon=True).start()

    def stop_capture(self):
        self.is_capturing = False
        if self.capture_process:
            self.capture_process.terminate()
        self.app.start_btn.config(text="Start")

    def run_tshark_capture(self):
        try:
            filter_str = self.app.filter_entry.get()
            self.capture_process = subprocess.Popen(
                [
                    "C:\\Program Files\\Wireshark\\tshark.exe",
                    "-i", self.interface,
                    "-Y", filter_str,
                    "-T", "fields",
                    "-e", "frame.number",
                    "-e", "frame.time",
                    "-e", "ip.src",
                    "-e", "ip.dst",
                    "-e", "frame.protocols",
                    "-e", "frame.len",
                    "-e", "_ws.col.Info"
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            while self.is_capturing:
                line = self.capture_process.stdout.readline()
                if not line:
                    break
                self.process_packet(line.strip())
        except Exception as e:
            Messagebox.show_error("Error", f"Capture failed: {str(e)}")
        finally:
            self.is_capturing = False
            self.app.root.after(0, lambda: self.app.start_btn.config(text="Start"))

    def process_packet(self, line):
        fields = line.split("\t")
        if len(fields) != 7:
            return
        packet = {
            "no": fields[0],
            "time": fields[1],
            "src": fields[2],
            "dst": fields[3],
            "protocol": fields[4],
            "length": fields[5],
            "info": fields[6]
        }
        self.app.threat_detector.analyze_packet(packet)

    def process_packet_queue(self):
        for _ in range(10):
            if self.packet_queue.empty():
                break
            packet = self.packet_queue.get()
            self.app.update_packet_display(packet)
        self.app.root.after(100, self.process_packet_queue)
