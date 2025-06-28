import ttkbootstrap as tb
from core.ui import setup_ui, setup_stats_tab
from core.capture import TSharkManager
from core.threats import ThreatDetector
from core.settings import SettingsManager
from core.nmap import NmapManager
from core.utils import get_geoip_reader

class WireSharkAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Wireshark Security Analyzer")
        self.root.geometry("1280x850")
        self.packet_queue = []
        
        # Settings
        self.settings = SettingsManager()
        self.model_name = self.settings.get("model_name", "deepseek-coder")

        # GeoIP
        self.geoip_reader = get_geoip_reader()

        # Setup UI
        setup_ui(self)
        setup_stats_tab(self)

        # External managers
        self.capture_manager = TSharkManager(self)
        self.nmap_manager = NmapManager(self)
        self.threat_detector = ThreatDetector(self)

        # Bindings
        self.root.bind('<Control-s>', lambda e: self.export_data())

    def on_closing(self):
        self.capture_manager.stop_capture()
        if self.geoip_reader:
            self.geoip_reader.close()
        self.root.destroy()
