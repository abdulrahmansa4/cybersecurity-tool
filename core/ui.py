# core/ui.py
import ttkbootstrap as tb
from tkinter.scrolledtext import ScrolledText
from ttkbootstrap.constants import *
from ttkbootstrap.dialogs import Messagebox
from tkinter import filedialog


def setup_ui(app):
    # Main Frame
    main_frame = tb.Frame(app.root, padding=10)
    main_frame.pack(fill=BOTH, expand=True)

    # Notebook Tabs
    app.notebook = tb.Notebook(main_frame)
    app.notebook.pack(fill=BOTH, expand=True)

    # Tabs
    app.tab_packets = tb.Frame(app.notebook)
    app.tab_threats = tb.Frame(app.notebook)
    app.tab_stats = tb.Frame(app.notebook)
    app.tab_settings = tb.Frame(app.notebook)
    app.tab_chat = tb.Frame(app.notebook)
    app.tab_nmap = tb.Frame(app.notebook)
    app.tab_pentest = tb.Frame(app.notebook)

    app.notebook.add(app.tab_packets, text="Live Packets")
    app.notebook.add(app.tab_threats, text="Threats")
    app.notebook.add(app.tab_stats, text="Statistics")
    app.notebook.add(app.tab_chat, text="AI Chat")
    app.notebook.add(app.tab_nmap, text="Nmap Analyzer")
    app.notebook.add(app.tab_settings, text="Settings")
    app.notebook.add(app.tab_pentest, text="Pentest Tools")

    # Status Bar
    app.status_var = tb.StringVar()
    status_bar = tb.Label(app.root, textvariable=app.status_var, relief=tb.SUNKEN, anchor="w")
    status_bar.pack(side=tb.BOTTOM, fill=tb.X)
    app.status_var.set("Ready")


def setup_stats_tab(app):
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

    fig = Figure(figsize=(5, 2), dpi=100)
    app.ax = fig.add_subplot(111)
    app.ax.set_title("Threats Over Time")
    app.ax.set_xlabel("Packet #")
    app.ax.set_ylabel("Threat Count")

    app.stats_canvas = FigureCanvasTkAgg(fig, master=app.tab_stats)
    app.stats_canvas.get_tk_widget().pack(fill=tb.BOTH, expand=True)
    app.stats_data = []
