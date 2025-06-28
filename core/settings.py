import json
import os

class SettingsManager:
    def __init__(self, path="settings/settings.json"):
        self.path = path
        self.settings = self.load()

    def load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                print(f"[!] Failed to load settings: {e}")
        return {
            "model_name": "deepseek-coder",
            "sound": True,
            "autoscroll": True,
            "darkmode": False,
            "autosave": False,
            "show_tooltips": True,
            "confirm_stop": True,
            "save_logs": True,
            "show_ai_explain": True,
            "show_ai_fix": True
        }

    def save(self):
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.settings, f, indent=2)
            return True
        except Exception as e:
            print(f"[!] Failed to save settings: {e}")
            return False

    def get(self, key, default=None):
        return self.settings.get(key, default)

    def set(self, key, value):
        self.settings[key] = value
        self.save()
