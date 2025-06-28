import re
import os
import geoip2.database
from ttkbootstrap.dialogs import Messagebox

def get_geoip_reader():
    try:
        db_path = os.path.join("data", "GeoLite2-Country.mmdb")
        if not os.path.exists(db_path):
            raise FileNotFoundError("GeoLite2-Country.mmdb not found in /data")
        return geoip2.database.Reader(db_path)
    except Exception as e:
        Messagebox.show_error("GeoIP Error", f"Could not open GeoLite2-Country.mmdb: {e}")
        return None

def get_country_flag(ip, geoip_reader=None):
    if not geoip_reader:
        return "Unknown"

    private_ranges = [
        re.compile(r"^10\."),
        re.compile(r"^192\.168\."),
        re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\.")
    ]
    if any(r.match(ip) for r in private_ranges):
        return "Private"

    try:
        response = geoip_reader.country(ip)
        country = response.country.name or "Unknown"
        code = response.country.iso_code or ""
        flag = ""
        if code and len(code) == 2:
            flag = chr(127397 + ord(code[0].upper())) + chr(127397 + ord(code[1].upper()))
        return f"{country} {flag}".strip()
    except Exception:
        return "Unknown"
