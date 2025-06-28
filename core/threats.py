# core/threats.py
import re
import requests
import time


class ThreatDetector:
    def __init__(self, app):
        self.app = app
        self.last_sound_time = 0
        self.threats = []

    def analyze_packet(self, packet):
        threat, explain, fix = self.detect_threat(packet)
        if threat:
            packet["threat"] = threat
            packet["ai_explain"] = explain
            packet["ai_fix"] = fix
            self.threats.append(packet)
        self.app.packets.append(packet)
        self.app.capture_manager.packet_queue.put(packet)

    def detect_threat(self, packet):
        info = packet["info"].lower()
        if "nmap" in info:
            return "Port Scan", "Detected Nmap scan", "Block suspicious IP"
        if "malware" in info:
            return "Malware", "Detected malware signature", "Quarantine the file"
        if "ddos" in info:
            return "DDoS Attack", "DDoS pattern observed", "Rate-limit offending IP"
        if re.search(r"(\d{1,3}\.){3}\d{1,3}", packet["info"]):
            return "IP Exposure", "Internal IP may be exposed", "Review firewall"

        prompt = self.generate_prompt(packet)
        try:
            response = requests.post(
                "http://localhost:11434/api/generate",
                json={
                    "model": self.app.model_name,
                    "prompt": prompt,
                    "stream": False
                },
                timeout=30
            )
            result = response.json()
            answer = result.get("response", "")
            if "no threat" in answer.lower():
                return None, "", ""
            return self.extract_ai_threat_data(answer)
        except Exception:
            return None, "", ""

    def generate_prompt(self, pkt):
        return (
            "Analyze the following packet. If it is a threat, respond with:\n"
            "Threat: <type>\nExplanation: <explanation>\nFix: <suggestion>\n"
            f"No: {pkt['no']}\nTime: {pkt['time']}\nSrc: {pkt['src']}\nDst: {pkt['dst']}\n"
            f"Protocol: {pkt['protocol']}\nLength: {pkt['length']}\nInfo: {pkt['info']}"
        )

    def extract_ai_threat_data(self, text):
        threat = explain = fix = ""
        for line in text.splitlines():
            if line.lower().startswith("threat:"):
                threat = line.split(":", 1)[1].strip()
            elif line.lower().startswith("explanation:"):
                explain = line.split(":", 1)[1].strip()
            elif line.lower().startswith("fix:"):
                fix = line.split(":", 1)[1].strip()
        return threat, explain, fix
