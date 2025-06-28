from core.app import WireSharkAnalyzer
import ttkbootstrap as tb

if __name__ == "__main__":
    root = tb.Window(themename="cyborg")
    app = WireSharkAnalyzer(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
