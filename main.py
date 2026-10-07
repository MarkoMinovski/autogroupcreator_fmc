import builtins
import csv
import ipaddress
import json
import os
import queue
import re
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from fmc_api_communicator import fmc_api_communicator


DEFAULT_FMC_URL = "https://fmcrestapisandbox.cisco.com"
DEFAULT_DOMAIN_UUID = "e276abec-e0f2-11e3-8169-6d9ed49b625f"  # replaced by the value FMC returns at login

# User-chosen name prefix; every object and group name is built from it, e.g.
#   <prefix>-HOST_192.0.2.10   <prefix>-URL_example.com   <prefix>-Imported-URLs
DEFAULT_NAME_PREFIX = "AGC"
NAME_PREFIX_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,39}")

# Frozen executables (PyInstaller etc.) don't ship the site module, so the
# exit() builtin used by fmc_api_communicator doesn't exist there. Restore it
# so the communicator's exit() raises SystemExit, which the GUI handles.
if not hasattr(builtins, "exit"):
    builtins.exit = sys.exit

# Config file lives next to the script, or next to the .exe when frozen.
# (In a --onefile build __file__ points at a temp folder, so use sys.executable.)
if getattr(sys, "frozen", False):
    APP_DIR = Path(sys.executable).resolve().parent
else:
    APP_DIR = Path(__file__).resolve().parent
CONFIG_PATH = APP_DIR / "fmc_config.json"
ENV_URL, ENV_USER, ENV_PASS = "FMC_URL", "FMC_USERNAME", "FMC_PASSWORD"

# Colour palette
C_BG = "#F3F6FA"        # window background
C_PANEL = "#FFFFFF"     # frames / entries
C_HEADER = "#0B3C5D"    # deep navy header
C_ACCENT = "#1D7FC4"    # primary blue
C_ACCENT_HOVER = "#166299"
C_ACCENT_DISABLED = "#9DB8CC"
C_SECONDARY = "#E1E8F0"
C_SECONDARY_HOVER = "#CFD9E4"
C_TEXT = "#1E2A38"
C_MUTED = "#5B6B7C"
C_DANGER = "#C62828"    # warning text on light backgrounds
C_LOG_BG = "#0F1B2A"
C_LOG_TEXT = "#D6E2F0"
C_LOG_INFO = "#6CB6F2"
C_LOG_OK = "#4ADE80"
C_LOG_WARN = "#FBBF24"
C_LOG_ERR = "#F87171"


# ---------------------------------------------------------------------------
# Config handling
# ---------------------------------------------------------------------------

def load_config():
    """Return dict with fmc_url, username, password, verify_ssl, ca_cert, name_prefix.
    Precedence: environment variables > config file > defaults."""
    cfg = {
        "fmc_url": DEFAULT_FMC_URL,
        "username": "",
        "password": "",
        "verify_ssl": False,
        "ca_cert": "",
        "name_prefix": DEFAULT_NAME_PREFIX,
    }
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            data = json.load(f)
        for key in cfg:
            if key in data:
                cfg[key] = data[key]
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as err:
        print("Could not read {}: {}".format(CONFIG_PATH, err))

    if not str(cfg["name_prefix"] or "").strip():
        cfg["name_prefix"] = DEFAULT_NAME_PREFIX  # nothing (or blank) saved in config

    cfg["fmc_url"] = os.environ.get(ENV_URL, cfg["fmc_url"])
    cfg["username"] = os.environ.get(ENV_USER, cfg["username"])
    cfg["password"] = os.environ.get(ENV_PASS, cfg["password"])
    return cfg


def save_config(cfg):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    try:
        os.chmod(CONFIG_PATH, 0o600)  # owner-only; no-op/ignored on some platforms
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Import logic
# ---------------------------------------------------------------------------

def build_url_object_name(prefix, url_value):
    return "{}-URL_{}".format(prefix, url_value)


def build_host_object_name(prefix, ip):
    return "{}-HOST_{}".format(prefix, ip)


def build_range_object_name(prefix, range_value):
    return "{}-RANGE_{}".format(prefix, range_value)


def build_network_group_name(prefix):
    return "{}-Imported-Hosts".format(prefix)


def build_url_group_name(prefix):
    return "{}-Imported-URLs".format(prefix)


def build_network_object_name(prefix, cidr_value):
    # "/" is replaced so the name stays safe for FMC object names;
    # the object's value keeps the real CIDR notation.
    return "{}-NET_{}".format(prefix, cidr_value.replace("/", "_"))


def parse_cidr(value):
    """Parse IPv4 CIDR notation. Returns (normalised_cidr, None) or (None, reason)."""
    try:
        return str(ipaddress.IPv4Network(value, strict=True)), None
    except ValueError as err:
        text = str(err)
        if "host bits set" in text:
            try:
                suggestion = ipaddress.IPv4Network(value, strict=False)
                return None, "host bits set (did you mean {}?)".format(suggestion)
            except ValueError:
                pass
        return None, "not a valid IPv4 CIDR block"


def classify_network_value(value):
    """Decide whether a 'network' row is a CIDR block or a start-end range.
    Returns (kind, normalised_value, reason): kind is 'cidr', 'range' or None."""
    if "/" in value:
        normalised, reason = parse_cidr(value)
        return ("cidr", normalised, None) if normalised else (None, None, reason)
    if "-" in value:
        normalised, reason = parse_ip_range(value)
        return ("range", normalised, None) if normalised else (None, None, reason)
    return None, None, "expected a CIDR block (10.0.0.0/24) or a range (10.0.0.1-10.0.0.50)"


def parse_ipv4(value):
    """Return the normalised IPv4 string, or None if invalid."""
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError:
        return None


def parse_ip_range(value):
    """Parse 'start-end' (IPv4). Returns (normalised_value, None) or (None, reason)."""
    parts = [p.strip() for p in value.split("-")]
    if len(parts) != 2:
        return None, "expected a range like 10.0.0.1-10.0.0.50"
    try:
        start = ipaddress.IPv4Address(parts[0])
        end = ipaddress.IPv4Address(parts[1])
    except ValueError:
        return None, "start or end is not a valid IPv4 address"
    if start > end:
        return None, "range start is higher than range end"
    return "{}-{}".format(start, end), None


def to_url_value(fqdn):
    # Leading "*." becomes a leading "." (FMC suffix match). Other wildcards are
    # approximated and reported; fully-wildcard entries are unusable.
    if fqdn.startswith('*.'):
        return '.' + fqdn[2:], None

    if '*' in fqdn:
        stripped = fqdn.replace('*', '')
        stripped = re.sub(r'\.\.+', '.', stripped).strip('.')
        if not stripped:
            return None, "unusable"
        return stripped, "approximated"

    return fqdn, None


def get_or_create_url_object(fmc, url_endpoint, url_value, cache, prefix):
    if url_value in cache:
        return cache[url_value]

    object_name = build_url_object_name(prefix, url_value)

    existing = fmc.getObjectByName(url_endpoint, object_name)
    if existing:
        cache[url_value] = existing
        return existing

    created = fmc.createObject(url_endpoint, {
        "name": object_name,
        "url": url_value,
        "type": "Url",
    })
    cache[url_value] = created
    return created


def get_or_create_host_object(fmc, host_endpoint, ip, cache, prefix):
    if ip in cache:
        return cache[ip]

    object_name = build_host_object_name(prefix, ip)

    existing = fmc.getObjectByName(host_endpoint, object_name)
    if existing:
        cache[ip] = existing
        return existing

    created = fmc.createObject(host_endpoint, {
        "name": object_name,
        "value": ip,
        "type": "Host",
    })
    cache[ip] = created
    return created


def get_or_create_range_object(fmc, range_endpoint, range_value, cache, prefix):
    # Same pattern as hosts/URLs: the name is derived from the value, so a
    # match by name already has the right value.
    if range_value in cache:
        return cache[range_value]

    object_name = build_range_object_name(prefix, range_value)

    existing = fmc.getObjectByName(range_endpoint, object_name)
    if existing:
        cache[range_value] = existing
        return existing

    created = fmc.createObject(range_endpoint, {
        "name": object_name,
        "value": range_value,
        "type": "Range",
    })
    cache[range_value] = created
    return created


def get_or_create_network_object(fmc, network_endpoint, cidr_value, cache, prefix):
    # CIDR blocks are FMC "Network" objects (/object/networks), distinct from "Range".
    if cidr_value in cache:
        return cache[cidr_value]

    object_name = build_network_object_name(prefix, cidr_value)

    existing = fmc.getObjectByName(network_endpoint, object_name)
    if existing:
        cache[cidr_value] = existing
        return existing

    created = fmc.createObject(network_endpoint, {
        "name": object_name,
        "value": cidr_value,
        "type": "Network",
    })
    cache[cidr_value] = created
    return created


def upsert_object(fmc, endpoint, name, object_json):
    existing = fmc.getObjectByName(endpoint, name)

    if existing:
        object_json["id"] = existing["id"]
        return fmc.updateObject(endpoint, existing["id"], object_json)

    return fmc.createObject(endpoint, object_json)


def run_import(fmc_ip, username, password, ssl_verify, ssl_cert, csv_path, name_prefix=DEFAULT_NAME_PREFIX):
    fmc = fmc_api_communicator(
        domain_uuid=DEFAULT_DOMAIN_UUID,
        fmc_user=username,
        fmc_password=password,
        ssl_verify=ssl_verify,
        ssl_cert=ssl_cert,
        fmc_ip=fmc_ip,
    )

    base = fmc_ip.rstrip('/')
    domain_url = "{}/api/fmc_config/v1/domain/{}".format(base, fmc.domain_uuid)

    host_endpoint = domain_url + "/object/hosts"
    range_endpoint = domain_url + "/object/ranges"
    network_endpoint = domain_url + "/object/networks"
    network_group_endpoint = domain_url + "/object/networkgroups"
    url_endpoint = domain_url + "/object/urls"
    url_group_endpoint = domain_url + "/object/urlgroups"

    host_cache, range_cache, cidr_cache, url_cache = {}, {}, {}, {}
    approximated, skipped = [], []

    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        headers = [(h or "").strip().lower() for h in (reader.fieldnames or [])]
        if "object" not in headers or "type" not in headers:
            raise ValueError("CSV header must be 'object,type' (found: {})".format(
                ",".join(reader.fieldnames or []) or "nothing"))

        for line_no, raw_row in enumerate(reader, start=2):  # line 1 is the header
            row = {(k or "").strip().lower(): (v or "").strip() for k, v in raw_row.items()}
            value = row.get("object", "")
            obj_type = row.get("type", "").lower()

            if not value and not obj_type:
                continue  # blank line

            if not value:
                skipped.append((line_no, value, "empty object value"))
                continue

            if obj_type == "ipv4":
                ip = parse_ipv4(value)
                if ip is None:
                    skipped.append((line_no, value, "not a valid IPv4 address"))
                    continue
                get_or_create_host_object(fmc, host_endpoint, ip, host_cache, name_prefix)

            elif obj_type == "network":
                kind, net_value, reason = classify_network_value(value)
                if kind is None:
                    skipped.append((line_no, value, reason))
                    continue
                if kind == "cidr":
                    get_or_create_network_object(fmc, network_endpoint, net_value, cidr_cache, name_prefix)
                else:
                    get_or_create_range_object(fmc, range_endpoint, net_value, range_cache, name_prefix)

            elif obj_type == "url":
                url_value, note = to_url_value(value)
                if url_value is None:
                    skipped.append((line_no, value, "unusable after wildcard conversion"))
                    continue
                if note == "approximated":
                    approximated.append((line_no, value, url_value))
                get_or_create_url_object(fmc, url_endpoint, url_value, url_cache, name_prefix)

            else:
                skipped.append((line_no, value, "unknown type '{}' (use url, ipv4 or network)".format(obj_type)))

    # Network groups can hold Host, Range and Network objects.
    network_members = (list(host_cache.values()) + list(range_cache.values())
                       + list(cidr_cache.values()))
    if network_members:
        group_name = build_network_group_name(name_prefix)
        upsert_object(fmc, network_group_endpoint, group_name, {
            "name": group_name,
            "type": "NetworkGroup",
            "objects": [{"type": o["type"], "id": o["id"]} for o in network_members],
        })

    if url_cache:
        group_name = build_url_group_name(name_prefix)
        upsert_object(fmc, url_group_endpoint, group_name, {
            "name": group_name,
            "type": "UrlGroup",
            "objects": [{"type": o["type"], "id": o["id"]} for o in url_cache.values()],
        })

    print("\nDone. {} host, {} range, {} network (CIDR) and {} URL objects processed.".format(
        len(host_cache), len(range_cache), len(cidr_cache), len(url_cache)))
    for line_no, original, converted in approximated:
        print("  line {}: '{}' approximated as '{}'".format(line_no, original, converted))
    for line_no, original, reason in skipped:
        print("  line {}: '{}' skipped ({})".format(line_no, original, reason))


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

class QueueWriter:
    """File-like object that sends print() output to a queue for the log box."""

    def __init__(self, q):
        self.q = q

    def write(self, text):
        if text:
            self.q.put(text)

    def flush(self):
        pass


class Tooltip:
    """Small hover tooltip for any widget."""

    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip = None
        widget.bind("<Enter>", self._show)
        widget.bind("<Leave>", self._hide)

    def _show(self, _event=None):
        if self.tip:
            return
        x = self.widget.winfo_rootx() + 16
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 6
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry("+{}+{}".format(x, y))
        tk.Label(self.tip, text=self.text, bg=C_HEADER, fg="#FFFFFF", relief="flat",
                 padx=8, pady=4, font=("Segoe UI", 9)).pack()

    def _hide(self, _event=None):
        if self.tip:
            self.tip.destroy()
            self.tip = None


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("FMC CSV Importer")
        self.geometry("1024x768")
        self.minsize(640, 540)
        self.configure(bg=C_BG)

        self.log_queue = queue.Queue()
        self.worker = None

        cfg = load_config()
        self.fmc_url_var = tk.StringVar(value=cfg["fmc_url"])
        self.user_var = tk.StringVar(value=cfg["username"])
        self.pass_var = tk.StringVar(value=cfg["password"])
        self.verify_var = tk.BooleanVar(value=bool(cfg["verify_ssl"]))
        self.cert_var = tk.StringVar(value=cfg["ca_cert"])
        self.save_pass_var = tk.BooleanVar(value=False)
        self.prefix_var = tk.StringVar(value=cfg["name_prefix"])
        self.save_prefix_var = tk.BooleanVar(value=False)
        self.csv_var = tk.StringVar()

        self._setup_style()
        self._build_ui()
        self._toggle_cert()
        self.after(100, self._drain_log)

    # -- styling -----------------------------------------------------------

    def _setup_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")  # most colour-friendly built-in theme

        style.configure(".", background=C_BG, foreground=C_TEXT, font=("Segoe UI", 10))
        style.configure("TFrame", background=C_BG)
        style.configure("TLabel", background=C_PANEL, foreground=C_TEXT)
        style.configure("Muted.TLabel", background=C_PANEL, foreground=C_MUTED, font=("Segoe UI", 9))
        style.configure("Warning.TLabel", background=C_PANEL, foreground=C_DANGER, font=("Segoe UI", 9, "bold"))

        style.configure("TLabelframe", background=C_PANEL, bordercolor=C_SECONDARY, relief="solid")
        style.configure("TLabelframe.Label", background=C_PANEL, foreground=C_HEADER,
                        font=("Segoe UI", 10, "bold"))

        style.configure("TEntry", fieldbackground="#FFFFFF", bordercolor="#B8C4D2",
                        lightcolor="#B8C4D2", darkcolor="#B8C4D2", padding=4)
        style.map("TEntry", bordercolor=[("focus", C_ACCENT)], lightcolor=[("focus", C_ACCENT)],
                  darkcolor=[("focus", C_ACCENT)])

        style.configure("TCheckbutton", background=C_PANEL, foreground=C_TEXT)
        style.map("TCheckbutton", background=[("active", C_PANEL)])

        style.configure("TButton", background=C_SECONDARY, foreground=C_TEXT, borderwidth=0,
                        padding=(12, 6), focuscolor=C_SECONDARY)
        style.map("TButton", background=[("active", C_SECONDARY_HOVER), ("disabled", C_SECONDARY)],
                  foreground=[("disabled", C_MUTED)])

        style.configure("Accent.TButton", background=C_ACCENT, foreground="#FFFFFF",
                        font=("Segoe UI", 11, "bold"), padding=(24, 8), focuscolor=C_ACCENT)
        style.map("Accent.TButton",
                  background=[("active", C_ACCENT_HOVER), ("disabled", C_ACCENT_DISABLED)],
                  foreground=[("disabled", "#FFFFFF")])

        style.configure("Vertical.TScrollbar", background=C_SECONDARY, troughcolor=C_LOG_BG,
                        bordercolor=C_LOG_BG, arrowcolor=C_TEXT)

    def _build_ui(self):
        pad = {"padx": 8, "pady": 5}

        # Header banner
        header = tk.Frame(self, bg=C_HEADER)
        header.pack(fill="x")
        tk.Label(header, text="FMC CSV Importer", bg=C_HEADER, fg="#FFFFFF",
                 font=("Segoe UI", 16, "bold")).pack(anchor="w", padx=16, pady=(12, 0))
        tk.Label(header, text="Create host, range, network and URL objects and groups from a CSV file", bg=C_HEADER,
                 fg="#9CC4E4", font=("Segoe UI", 9)).pack(anchor="w", padx=16, pady=(0, 12))
        tk.Label(header, text="Contact: minovskimarco@gmail.com", bg=C_HEADER,
                 fg="#9CC4E4", font=("Segoe UI", 8)).pack(anchor="w", padx=16, pady=(0, 6))
        tk.Frame(self, bg=C_ACCENT, height=3).pack(fill="x")

        body = ttk.Frame(self)
        body.pack(fill="both", expand=True, padx=12, pady=10)

        # Connection
        creds = ttk.LabelFrame(body, text=" FMC connection ")
        creds.pack(fill="x", pady=(0, 8))
        creds.columnconfigure(1, weight=1)

        ttk.Label(creds, text="FMC URL:").grid(row=0, column=0, sticky="w", **pad)
        ttk.Entry(creds, textvariable=self.fmc_url_var).grid(row=0, column=1, columnspan=2, sticky="ew", **pad)

        ttk.Label(creds, text="Username:").grid(row=1, column=0, sticky="w", **pad)
        ttk.Entry(creds, textvariable=self.user_var).grid(row=1, column=1, columnspan=2, sticky="ew", **pad)

        ttk.Label(creds, text="Password:").grid(row=2, column=0, sticky="w", **pad)
        ttk.Entry(creds, textvariable=self.pass_var, show="*").grid(row=2, column=1, columnspan=2, sticky="ew", **pad)

        ssl_row = tk.Frame(creds, bg=C_PANEL)
        ssl_row.grid(row=3, column=0, columnspan=3, sticky="w", **pad)
        ttk.Checkbutton(ssl_row, text="Verify SSL certificate", variable=self.verify_var,
                        command=self._toggle_cert).pack(side="left")
        ssl_help = tk.Label(ssl_row, text="(?)", bg=C_PANEL, fg=C_ACCENT, cursor="question_arrow",
                            font=("Segoe UI", 9, "bold"))
        ssl_help.pack(side="left", padx=(6, 0))
        Tooltip(ssl_help, "Untested. Contact me if you encounter any problems")

        ttk.Label(creds, text="CA cert file:").grid(row=4, column=0, sticky="w", **pad)
        self.cert_entry = ttk.Entry(creds, textvariable=self.cert_var)
        self.cert_entry.grid(row=4, column=1, sticky="ew", **pad)
        self.cert_btn = ttk.Button(creds, text="Browse...", command=self._browse_cert)
        self.cert_btn.grid(row=4, column=2, **pad)

        # Config row
        cfg_row = ttk.Frame(creds, style="TFrame")
        cfg_row.grid(row=5, column=0, columnspan=3, sticky="ew", padx=8, pady=(2, 8))
        cfg_row.configure(style="TFrame")
        ttk.Button(cfg_row, text="Reload config", command=self._reload_config).pack(side="left")
        ttk.Button(cfg_row, text="Save to config", command=self._save_config).pack(side="left", padx=(6, 10))
        ttk.Checkbutton(cfg_row, text="Include password (stored as plain text)",
                        variable=self.save_pass_var).pack(side="left")
        ttk.Label(creds, text="Config: {}   |   Env overrides: {}, {}, {}".format(
            CONFIG_PATH.name, ENV_URL, ENV_USER, ENV_PASS), style="Muted.TLabel"
        ).grid(row=6, column=0, columnspan=3, sticky="w", padx=8, pady=(0, 8))

        # Naming
        naming = ttk.LabelFrame(body, text=" Object naming ")
        naming.pack(fill="x", pady=(0, 8))
        naming.columnconfigure(1, weight=1)
        ttk.Label(naming, text="Name prefix:").grid(row=0, column=0, sticky="w", **pad)
        ttk.Entry(naming, textvariable=self.prefix_var).grid(row=0, column=1, sticky="ew", **pad)
        ttk.Checkbutton(naming, text="Include in config when saving",
                        variable=self.save_prefix_var).grid(row=0, column=2, sticky="w", **pad)
        self.prefix_preview = ttk.Label(naming, text="", style="Muted.TLabel")
        self.prefix_preview.grid(row=1, column=0, columnspan=3, sticky="w", padx=8, pady=(0, 4))
        ttk.Label(
            naming,
            text=("Warning: running the same input file with a different prefix creates a new set of "
                  "objects, because existing objects are looked up by name. This can result in "
                  "duplicate objects in FMC."),
            style="Warning.TLabel", wraplength=660, justify="left",
        ).grid(row=2, column=0, columnspan=3, sticky="w", padx=8, pady=(0, 8))
        self.prefix_var.trace_add("write", lambda *_: self._update_prefix_preview())
        self._update_prefix_preview()

        # CSV
        csv_frame = ttk.LabelFrame(body, text=" Input CSV (columns: object,type - type is url, ipv4 or network) ")
        csv_frame.pack(fill="x", pady=(0, 8))
        csv_frame.columnconfigure(0, weight=1)
        ttk.Entry(csv_frame, textvariable=self.csv_var).grid(row=0, column=0, sticky="ew", **pad)
        ttk.Button(csv_frame, text="Browse...", command=self._browse_csv).grid(row=0, column=1, **pad)

        # Run
        self.run_btn = ttk.Button(body, text="Run import", style="Accent.TButton", command=self._start)
        self.run_btn.pack(pady=4)

        # Log
        log_frame = ttk.LabelFrame(body, text=" Log ")
        log_frame.pack(fill="both", expand=True, pady=(4, 0))
        self.log = tk.Text(log_frame, wrap="word", state="disabled", height=10, bg=C_LOG_BG,
                           fg=C_LOG_TEXT, insertbackground=C_LOG_TEXT, relief="flat",
                           font=("Consolas", 9), padx=8, pady=6)
        scroll = ttk.Scrollbar(log_frame, command=self.log.yview)
        self.log.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.log.pack(side="left", fill="both", expand=True)

        self.log.tag_configure("info", foreground=C_LOG_INFO)
        self.log.tag_configure("ok", foreground=C_LOG_OK)
        self.log.tag_configure("warn", foreground=C_LOG_WARN)
        self.log.tag_configure("err", foreground=C_LOG_ERR)
        self.log.tag_configure("banner", foreground="#FFFFFF", font=("Consolas", 9, "bold"))

    # -- config actions ------------------------------------------------------

    def _reload_config(self):
        cfg = load_config()
        self.fmc_url_var.set(cfg["fmc_url"])
        self.user_var.set(cfg["username"])
        self.pass_var.set(cfg["password"])
        self.verify_var.set(bool(cfg["verify_ssl"]))
        self.cert_var.set(cfg["ca_cert"])
        self.prefix_var.set(cfg["name_prefix"])
        self._toggle_cert()
        self._append_log("Config reloaded from {} (and environment).\n".format(CONFIG_PATH.name), "info")

    def _save_config(self):
        cfg = {
            "fmc_url": self.fmc_url_var.get().strip(),
            "username": self.user_var.get().strip(),
            "password": self.pass_var.get() if self.save_pass_var.get() else "",
            "verify_ssl": self.verify_var.get(),
            "ca_cert": self.cert_var.get().strip(),
        }
        # Opt-in, like the password: only written when the tick box is set.
        if self.save_prefix_var.get():
            cfg["name_prefix"] = self.prefix_var.get().strip()
        try:
            save_config(cfg)
        except OSError as err:
            messagebox.showerror("Save failed", "Could not write {}:\n{}".format(CONFIG_PATH, err))
            return
        note = " (password {}, prefix {})".format(
            "included" if cfg["password"] else "not saved",
            "included" if "name_prefix" in cfg else "not saved")
        self._append_log("Saved settings to {}{}.\n".format(CONFIG_PATH, note), "ok")

    # -- widget helpers ------------------------------------------------------

    def _update_prefix_preview(self):
        prefix = self.prefix_var.get().strip() or "<prefix>"
        self.prefix_preview.configure(
            text="e.g. {p}-HOST_192.0.2.10   {p}-URL_example.com   groups: {p}-Imported-Hosts, {p}-Imported-URLs".format(p=prefix))

    def _toggle_cert(self):
        state = "normal" if self.verify_var.get() else "disabled"
        self.cert_entry.configure(state=state)
        self.cert_btn.configure(state=state)

    def _browse_cert(self):
        path = filedialog.askopenfilename(
            title="Select CA certificate",
            filetypes=[("Certificates", "*.pem *.crt *.cer"), ("All files", "*.*")],
        )
        if path:
            self.cert_var.set(path)

    def _browse_csv(self):
        path = filedialog.askopenfilename(
            title="Select CSV file",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if path:
            self.csv_var.set(path)

    # -- logging -------------------------------------------------------------

    @staticmethod
    def _classify(text):
        low = text.lower()
        if text.strip().startswith("==="):
            return "banner"
        if any(w in low for w in ("error", "failure", "failed", "exited", "stopped", "not found")):
            return "err"
        if any(w in low for w in ("approximated", "skipped", "retrying")):
            return "warn"
        if any(w in low for w in ("success", "done.", "finished", "saved")):
            return "ok"
        if any(w in low for w in ("sending", "creating", "updating", "retrieving", "looking up",
                                  "fetching", "deleting")):
            return "info"
        return None

    def _append_log(self, text, tag=None):
        if tag is None:
            tag = self._classify(text)
        self.log.configure(state="normal")
        if tag:
            self.log.insert("end", text, tag)
        else:
            self.log.insert("end", text)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _drain_log(self):
        try:
            while True:
                self._append_log(self.log_queue.get_nowait())
        except queue.Empty:
            pass
        self.after(100, self._drain_log)

    # -- running -------------------------------------------------------------

    def _start(self):
        fmc_url = self.fmc_url_var.get().strip()
        username = self.user_var.get().strip()
        password = self.pass_var.get()
        csv_path = self.csv_var.get().strip()
        verify = self.verify_var.get()
        cert = self.cert_var.get().strip()
        prefix = self.prefix_var.get().strip()

        if not (fmc_url and username and password and csv_path):
            messagebox.showwarning("Missing input", "FMC URL, username, password and a CSV file are all required.")
            return
        if not fmc_url.startswith(("http://", "https://")):
            messagebox.showwarning("Invalid URL", "FMC URL must start with https:// (or http://).")
            return
        if verify and not cert:
            messagebox.showwarning("Missing certificate", "Select a CA certificate file or turn off SSL verification.")
            return

        if not NAME_PREFIX_PATTERN.fullmatch(prefix):
            messagebox.showwarning(
                "Invalid name prefix",
                "The name prefix must be 1-40 characters, start with a letter or digit, and contain only "
                "letters, digits, '.', '_' or '-'.")
            return

        self.run_btn.configure(state="disabled")
        self._append_log("\n=== Starting import ===\n", "banner")
        self.worker = threading.Thread(
            target=self._work, args=(fmc_url, username, password, verify, cert, csv_path, prefix), daemon=True
        )
        self.worker.start()

    def _work(self, fmc_url, username, password, verify, cert, csv_path, prefix):
        # The communicator uses print() and calls exit() on failure, so capture
        # stdout for the log box and catch SystemExit here in the worker thread.
        old_stdout = sys.stdout
        sys.stdout = QueueWriter(self.log_queue)
        try:
            run_import(fmc_url, username, password, verify, cert, csv_path, prefix)
            self.log_queue.put("\n=== Finished ===\n")
        except SystemExit:
            self.log_queue.put("\n=== Stopped: the FMC communicator exited after an error (see log above) ===\n")
        except Exception as err:
            self.log_queue.put("\n=== Error: {} ===\n".format(err))
        finally:
            sys.stdout = old_stdout
            self.after(0, lambda: self.run_btn.configure(state="normal"))


if __name__ == "__main__":
    App().mainloop()