# How to Start the WireShark Security Analyzer App

## 1. Install Requirements

First, install all required Python packages.  
Open a terminal in this folder and run:

```
pip install -r requirements.txt
```

## 2. Install Wireshark

- Download and install Wireshark from [https://www.wireshark.org/download.html](https://www.wireshark.org/download.html)
- Make sure `tshark.exe` is installed (it comes with Wireshark).

## 3. Download GeoLite2 Database

- Download the GeoLite2-Country.mmdb from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
- Place the `GeoLite2-Country.mmdb` file in the same folder as `wire.py`.

## 4. (Optional) Start the AI Backend

- If you want to use AI features, make sure the backend (e.g., DeepSeek or Ollama) is running at `http://localhost:11434`.

## 5. Run the App

Start the application with:

```
python wire.py
```

## 6. Usage

- Select a network interface and click "Start" to begin capturing packets.
- Use the tabs for live packets, threats, statistics, AI chat, Nmap analyzer, and pentest tools.
- Export data or reports as needed.

---

**Note:**  
- You must run the app as Administrator to capture packets on Windows.
- Some features require internet access or additional
