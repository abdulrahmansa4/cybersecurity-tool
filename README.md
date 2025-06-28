### 📄 `README.md`

# 🛡️ WireShark Security Analyzer

A powerful desktop application for live packet inspection, AI-powered threat detection, and pentesting tools — all wrapped in a modern Tkinter interface.

---

## 📦 Features

- ✅ Real-time packet capture using `tshark`
- 🔍 AI-based threat detection and explanations
- 🌍 Country + flag resolution from GeoLite2
- 📊 Statistics visualization via Matplotlib
- 🧠 Chat with a local AI assistant (Ollama or DeepSeek)
- ⚙️ Advanced Nmap analyzer and pentest tools
- 📁 Export reports as JSON, CSV, PDF, or DOCX

---

## 🚀 Getting Started

### 1. Install Python Requirements

From the project root:

```bash
pip install -r requirements.txt
```

> **Tip:** Use a virtual environment if desired.

---

### 2. Install Wireshark + Tshark

- Download Wireshark: [https://www.wireshark.org/download.html](https://www.wireshark.org/download.html)
- Ensure **TShark** is installed (enable it during setup)
- Confirm it's working:

````bash
"C:\Program Files\Wireshark\tshark.exe" -D


---

### 3. Download GeoLite2-Country Database

* Create a free MaxMind account at:
  [https://dev.maxmind.com/geoip/geolite2-free-geolocation-data](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)

* Download and extract the latest `.tar.gz` file.

* Copy `GeoLite2-Country.mmdb` into:

```bash
/data/GeoLite2-Country.mmdb
````

---

### 4. (Optional) Start the AI Backend

To enable AI features (chat, threat analysis, Nmap summary):

- Install and run [Ollama](https://ollama.com/) or another compatible API
- Confirm it's accessible at:

```
http://localhost:11434
```

---

### 5. Run the Application

From the terminal:

```bash
python wire.py
```

> ✅ **Run as Administrator on Windows** to enable packet capture.

---

### 🧭 Usage Overview

| Tab               | Description                                  |
| ----------------- | -------------------------------------------- |
| **Live Packets**  | View captured packets in real-time           |
| **Threats**       | Detected threats + AI explanations/fixes     |
| **Statistics**    | Threat trends and visual insights            |
| **AI Chat**       | Ask questions or analyze data interactively  |
| **Nmap Analyzer** | Run scans and get annotated output           |
| **Pentest Tools** | Run traceroute, ping, whois, and more        |
| **Settings**      | Toggle dark mode, sounds, AI, tooltips, etc. |

---

## 📁 Project Structure

```
cybersecurity-tool/
├── wire.py                     # 🔁 Entry point
├── requirements.txt
├── README.md
├── analyzer.log
├── data/
│   ├── GeoLite2-Country.mmdb
│   └── GeoLite2-Country_20250610.tar.gz
├── logs/
│   └── analyzer.log
├── settings/
│   └── settings.json
├── core/
│   ├── __init__.py
│   ├── app.py
│   ├── capture.py
│   ├── threats.py
│   ├── nmap.py
│   ├── ui.py
│   ├── utils.py
│   └── settings.py
└── assets/
    └── icons/ (optional)
```

---

## 📝 Notes

- ⚠️ Requires administrator permissions for packet capture on Windows
- 🛠️ Logs are written to `logs/analyzer.log`
- 🌍 Internet is required for some pentest tools and AI prompts

---
