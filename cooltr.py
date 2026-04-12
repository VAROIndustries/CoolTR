#!/usr/bin/env python3
"""
CoolTR — Cool TraceRoute
Windows network diagnostic: live MTR traceroute, continuous ping stats,
DNS, GeoIP, ARIN/RDAP, BGP, and WHOIS lookups in one dark-themed window.
"""

import tkinter as tk
from tkinter import ttk
import threading
import socket
import subprocess
import re
import time
import math
from collections import deque
from datetime import datetime

try:
    import requests
    HAS_REQ = True
except ImportError:
    HAS_REQ = False

try:
    import dns.resolver as _dns_resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import whois as _pywhois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False


# ─── Theme ─────────────────────────────────────────────────────────────────────
C = {
    "bg":     "#0d1117",
    "panel":  "#161b22",
    "widget": "#21262d",
    "border": "#30363d",
    "fg":     "#c9d1d9",
    "dim":    "#8b949e",
    "accent": "#58a6ff",
    "green":  "#3fb950",
    "yellow": "#d29922",
    "orange": "#db6d28",
    "red":    "#f85149",
}
MONO    = ("Consolas", 9)
MONO_SM = ("Consolas", 8)
UI      = ("Segoe UI", 9)
UI_B    = ("Segoe UI", 9, "bold")


# ─── System ping helper (no admin/raw-socket needed) ──────────────────────────
def _ping(host, ttl=None, timeout_ms=2000):
    """
    Calls Windows ping.exe.
    Returns (src_ip, rtt_ms_or_None, ttl_expired_bool).
    """
    cmd = ["ping", "-n", "1", "-w", str(timeout_ms)]
    if ttl is not None:
        cmd += ["-i", str(ttl)]
    cmd.append(host)
    try:
        out = subprocess.check_output(
            cmd,
            stderr=subprocess.DEVNULL,
            timeout=(timeout_ms / 1000) + 3,
            creationflags=subprocess.CREATE_NO_WINDOW,
        ).decode(errors="replace")
    except Exception:
        return None, None, False

    ip_m  = re.search(r"Reply from ([\d.]+)", out)
    rtt_m = re.search(r"time[<=>]+(\d+)ms", out)
    expired = "TTL expired" in out or "TTL Expired" in out

    ip  = ip_m.group(1) if ip_m else None
    rtt = int(rtt_m.group(1)) if rtt_m else (0 if ip and "time<" in out else None)
    return ip, rtt, expired


# ─── Hop statistics ────────────────────────────────────────────────────────────
class Hop:
    def __init__(self, n):
        self.n    = n
        self.ip   = ""
        self.host = ""
        self.sent = 0
        self.recv = 0
        self.last = None
        self._rtts = deque(maxlen=300)
        self._lock = threading.Lock()

    def record(self, rtt):
        with self._lock:
            self.recv += 1
            self.last  = rtt
            if rtt is not None:
                self._rtts.append(rtt)

    @property
    def loss(self):
        return 100.0 * (self.sent - self.recv) / self.sent if self.sent else 0.0

    @property
    def avg(self):
        d = list(self._rtts); return sum(d) / len(d) if d else None

    @property
    def best(self):
        d = list(self._rtts); return min(d) if d else None

    @property
    def worst(self):
        d = list(self._rtts); return max(d) if d else None

    @property
    def stdev(self):
        d = list(self._rtts)
        if len(d) < 2:
            return None
        a = sum(d) / len(d)
        return math.sqrt(sum((x - a) ** 2 for x in d) / len(d))

    @staticmethod
    def ms(v, dec=1):
        return f"{v:.{dec}f}" if v is not None else "—"


# ─── MTR Engine ────────────────────────────────────────────────────────────────
class MTR:
    """
    Phase 1 — stream tracert output to discover route hop-by-hop.
    Phase 2 — each discovered hop gets its own persistent probe thread.
    UI receives snapshot every 0.5 s via callback.
    """

    def __init__(self, target, callback):
        self.target      = target
        self.cb          = callback
        self.hops        = {}            # int ttl -> Hop
        self.running     = False
        self._lock       = threading.Lock()
        self._target_ip  = ""
        self._max_ttl    = 0
        self._rcache     = {}            # ip -> hostname
        self._started_probes = set()     # ttls already having probe threads

    def start(self):
        self.running = True
        try:
            self._target_ip = socket.gethostbyname(self.target)
        except Exception:
            self._target_ip = self.target
        threading.Thread(target=self._discover, daemon=True).start()
        threading.Thread(target=self._ui_clock, daemon=True).start()

    def stop(self):
        self.running = False

    # ── internals ──────────────────────────────────────────────────────────────

    def _get_hop(self, n):
        with self._lock:
            if n not in self.hops:
                self.hops[n] = Hop(n)
            return self.hops[n]

    def _resolve(self, ip):
        if ip in self._rcache:
            return self._rcache[ip]
        try:
            h = socket.gethostbyaddr(ip)[0]
        except Exception:
            h = ""
        self._rcache[ip] = h
        return h

    def _ensure_probe(self, ttl):
        if ttl in self._started_probes:
            return
        self._started_probes.add(ttl)
        threading.Thread(target=self._probe_loop, args=(ttl,), daemon=True).start()

    def _discover(self):
        """Stream tracert; start probe threads as hops are found."""
        try:
            proc = subprocess.Popen(
                ["tracert", "-d", "-w", "1500", "-h", "30", self.target],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            for raw in proc.stdout:
                if not self.running:
                    proc.terminate()
                    return
                line = raw.decode(errors="replace")
                m = re.match(r"\s*(\d+)\s+", line)
                if not m:
                    continue
                ttl = int(m.group(1))
                hop = self._get_hop(ttl)

                with self._lock:
                    self._max_ttl = max(self._max_ttl, ttl)

                ips = re.findall(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
                if ips:
                    with self._lock:
                        hop.ip = ips[-1]
                    ip_copy = ips[-1]
                    threading.Thread(
                        target=lambda h=hop, ip=ip_copy: setattr(h, "host", self._resolve(ip)),
                        daemon=True,
                    ).start()

                self._ensure_probe(ttl)
            proc.wait()
        except Exception:
            pass

        # Fallback if tracert found nothing
        if self._max_ttl == 0:
            self._max_ttl = 30
            for ttl in range(1, 31):
                self._ensure_probe(ttl)

    def _probe_loop(self, ttl):
        """Continuously ping the target with a fixed TTL, updating this hop's stats."""
        while self.running:
            t0 = time.time()
            hop = self._get_hop(ttl)

            with self._lock:
                hop.sent += 1

            ip, rtt, expired = _ping(self.target, ttl=ttl, timeout_ms=2000)

            if ip:
                with self._lock:
                    if ip != hop.ip:
                        hop.ip   = ip
                        hop.host = ""
                    if not hop.host:
                        ip_copy = ip
                        threading.Thread(
                            target=lambda h=hop, i=ip_copy: setattr(h, "host", self._resolve(i)),
                            daemon=True,
                        ).start()

            if rtt is not None:
                hop.record(rtt)

            elapsed = time.time() - t0
            if self.running:
                time.sleep(max(0.0, 2.0 - elapsed))

    def _ui_clock(self):
        while self.running:
            time.sleep(0.5)
            with self._lock:
                snap = dict(self.hops)
            self.cb(snap)

    def snapshot(self):
        with self._lock:
            return dict(self.hops)


# ─── Ping Engine ───────────────────────────────────────────────────────────────
class Pinger:
    def __init__(self, target, callback):
        self.target   = target
        self.cb       = callback
        self.running  = False
        self.sent     = 0
        self.recv     = 0
        self.last     = None
        self._rtts    = deque(maxlen=1000)
        self._history = deque(maxlen=500)

    def start(self):
        self.running = True
        threading.Thread(target=self._run, daemon=True).start()

    def stop(self):
        self.running = False

    def _run(self):
        while self.running:
            t0 = time.time()
            self.sent += 1
            ip, rtt, _ = _ping(self.target, timeout_ms=2000)
            ts = datetime.now().strftime("%H:%M:%S")

            if rtt is not None:
                self.recv += 1
                self.last = rtt
                self._rtts.append(rtt)
                self._history.append((ts, rtt, ip or self.target))
            else:
                self.last = None
                self._history.append((ts, None, ip or self.target))

            self.cb(self._stats())
            elapsed = time.time() - t0
            if self.running:
                time.sleep(max(0.0, 1.0 - elapsed))

    def _stats(self):
        d   = list(self._rtts)
        avg = sum(d) / len(d) if d else None
        std = None
        if len(d) >= 2:
            std = math.sqrt(sum((x - avg) ** 2 for x in d) / len(d))
        hist = list(self._history)
        return {
            "sent": self.sent, "recv": self.recv,
            "loss": 100.0 * (self.sent - self.recv) / self.sent if self.sent else 0.0,
            "last": self.last, "avg": avg,
            "best": min(d) if d else None,
            "worst": max(d) if d else None,
            "stdev": std,
            "latest": hist[-1] if hist else None,
        }


# ─── Info / Lookup Engine ──────────────────────────────────────────────────────
class Lookup:
    def __init__(self, target, callback):
        self.target = target
        self.cb     = callback

    def start(self):
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        self.cb({"section": "dns",   "data": self._dns()})
        if HAS_REQ:
            self.cb({"section": "geoip", "data": self._geoip()})
            self.cb({"section": "arin",  "data": self._arin()})
            self.cb({"section": "bgp",   "data": self._bgp()})
        else:
            self.cb({"section": "geoip", "data": "pip install requests to enable"})
            self.cb({"section": "arin",  "data": "pip install requests to enable"})
            self.cb({"section": "bgp",   "data": "pip install requests to enable"})
        self.cb({"section": "whois", "data": self._whois()})

    def _resolve_ip(self):
        try:
            return socket.gethostbyname(self.target)
        except Exception:
            return self.target

    # ── DNS ──────────────────────────────────────────────────────────────────
    def _dns(self):
        ip = self._resolve_ip()
        lines = [f"{'A':8}: {ip}"]

        try:
            host, _, _ = socket.gethostbyaddr(ip)
            lines.append(f"{'PTR':8}: {host}")
        except Exception:
            pass

        if HAS_DNS:
            r = _dns_resolver.Resolver()
            r.lifetime = 5
            for rtype in ("AAAA", "MX", "NS", "TXT", "SOA", "CNAME"):
                try:
                    ans = r.resolve(self.target, rtype)
                    for a in ans:
                        lines.append(f"{rtype:8}: {a}")
                except Exception:
                    pass
        else:
            lines.append("")
            lines.append("(install dnspython for full DNS records)")

        return "\n".join(lines)

    # ── GeoIP ─────────────────────────────────────────────────────────────────
    def _geoip(self):
        ip = self._resolve_ip()
        try:
            d = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,"
                "regionName,city,zip,lat,lon,timezone,isp,org,as,query",
                timeout=5,
            ).json()
            if d.get("status") == "success":
                return "\n".join([
                    f"{'IP':8}: {d.get('query','')}",
                    f"{'ASN':8}: {d.get('as','')}",
                    f"{'ISP':8}: {d.get('isp','')}",
                    f"{'Org':8}: {d.get('org','')}",
                    f"{'Country':8}: {d.get('country','')} ({d.get('countryCode','')})",
                    f"{'Region':8}: {d.get('regionName','')}",
                    f"{'City':8}: {d.get('city','')}",
                    f"{'ZIP':8}: {d.get('zip','')}",
                    f"{'Lat/Lon':8}: {d.get('lat','')}, {d.get('lon','')}",
                    f"{'TZ':8}: {d.get('timezone','')}",
                ])
        except Exception as e:
            return f"Error: {e}"
        return "No data"

    # ── ARIN RDAP ─────────────────────────────────────────────────────────────
    def _arin(self):
        ip = self._resolve_ip()
        try:
            d = requests.get(
                f"https://rdap.arin.net/registry/ip/{ip}",
                timeout=6,
                headers={"Accept": "application/json"},
            ).json()
            lines = []
            for key, label in [("handle","Handle"), ("name","Name"), ("country","Country"),
                                ("type","Type"), ("ipVersion","IPv")]:
                if key in d:
                    lines.append(f"{label:8}: {d[key]}")
            sa, ea = d.get("startAddress",""), d.get("endAddress","")
            if sa:
                lines.append(f"{'Range':8}: {sa} – {ea}")
            cidrs = [c.get("v4prefix") or c.get("v6prefix","") for c in d.get("cidr0_cidrs",[])]
            if cidrs:
                lines.append(f"{'CIDRs':8}: {', '.join(filter(None, cidrs))}")
            for ent in d.get("entities", []):
                roles = ent.get("roles", [])
                vcard = ent.get("vcardArray", [None, []])[1]
                fn = next((v[3] for v in vcard if v[0] == "fn"), "")
                email = next((v[3] for v in vcard if v[0] == "email"), "")
                if fn:
                    label = "/".join(roles)[:8]
                    lines.append(f"{label:8}: {fn}" + (f" <{email}>" if email else ""))
            # Remarks
            for rem in d.get("remarks", [])[:2]:
                desc = rem.get("description", [])
                if desc:
                    lines.append(f"{'Note':8}: {desc[0][:60]}")
            return "\n".join(lines) if lines else "No ARIN data"
        except Exception as e:
            return f"Error: {e}"

    # ── BGP ──────────────────────────────────────────────────────────────────
    def _bgp(self):
        ip = self._resolve_ip()
        try:
            d = requests.get(f"https://api.bgpview.io/ip/{ip}", timeout=8).json()
            if d.get("status") == "ok":
                lines = []
                for prefix in d["data"].get("prefixes", [])[:4]:
                    lines.append(f"Prefix : {prefix.get('prefix','')}")
                    asn_info = prefix.get("asn", {})
                    if asn_info:
                        lines.append(f"  ASN  : AS{asn_info.get('asn','')}  {asn_info.get('description','')}")
                        lines.append(f"  CC   : {asn_info.get('country_code','')}")
                    roa = prefix.get("roa_status","")
                    if roa:
                        lines.append(f"  ROA  : {roa}")
                return "\n".join(lines) if lines else "No BGP data"
        except Exception as e:
            return f"Error: {e}"
        return "No data"

    # ── WHOIS ─────────────────────────────────────────────────────────────────
    def _whois(self):
        if HAS_WHOIS:
            try:
                w = _pywhois.whois(self.target)
                text = str(w)
                lines = [l for l in text.split("\n") if l.strip()]
                return "\n".join(lines[:100])
            except Exception as e:
                return f"Error: {e}"
        # Fallback: system whois command
        try:
            out = subprocess.check_output(
                ["whois", self.target],
                stderr=subprocess.DEVNULL,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,
            ).decode(errors="replace")
            lines = [l for l in out.split("\n")
                     if l.strip() and not l.startswith(("%", "#", ";"))]
            return "\n".join(lines[:100])
        except Exception as e:
            return f"WHOIS unavailable: {e}\n(pip install python-whois)"


# ─── Main Application ──────────────────────────────────────────────────────────
class CoolTR(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CoolTR — Cool TraceRoute")
        self.geometry("1480x840")
        self.minsize(1100, 650)
        self.configure(bg=C["bg"])

        self._mtr     = None
        self._pinger  = None
        self._lookup  = None
        self._running = False

        self._build()
        self._apply_style()
        self._target.focus_set()

    # ── Build ───────────────────────────────────────────────────────────────────

    def _build(self):
        self._build_header()

        body = tk.Frame(self, bg=C["bg"])
        body.pack(fill="both", expand=True, padx=4, pady=(0, 4))

        # Left: info panel
        left = tk.Frame(body, bg=C["panel"], width=340)
        left.pack(side="left", fill="y", padx=(0, 4))
        left.pack_propagate(False)
        self._build_info_panel(left)

        # Right: MTR (top) + Ping (bottom)
        right = tk.Frame(body, bg=C["bg"])
        right.pack(side="left", fill="both", expand=True)

        mtr_f = tk.Frame(right, bg=C["panel"])
        mtr_f.pack(fill="both", expand=True, pady=(0, 4))
        self._build_mtr(mtr_f)

        ping_f = tk.Frame(right, bg=C["panel"], height=210)
        ping_f.pack(fill="x")
        ping_f.pack_propagate(False)
        self._build_ping(ping_f)

    def _build_header(self):
        hdr = tk.Frame(self, bg=C["panel"], height=48)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        tk.Label(hdr, text="CoolTR", bg=C["panel"], fg=C["accent"],
                 font=("Segoe UI", 13, "bold")).pack(side="left", padx=(12, 4), pady=8)
        tk.Label(hdr, text="·  Cool TraceRoute", bg=C["panel"], fg=C["dim"],
                 font=("Segoe UI", 10)).pack(side="left", pady=8)

        tk.Frame(hdr, bg=C["border"], width=1).pack(side="left", fill="y", padx=14, pady=8)

        tk.Label(hdr, text="Target:", bg=C["panel"], fg=C["dim"],
                 font=UI).pack(side="left", padx=(0, 5))

        self._target_var = tk.StringVar()
        self._target = tk.Entry(
            hdr, textvariable=self._target_var,
            bg=C["widget"], fg=C["fg"], insertbackground=C["fg"],
            relief="flat", bd=5, font=("Consolas", 11), width=28,
        )
        self._target.pack(side="left", ipady=3)
        self._target.bind("<Return>", lambda e: self._toggle())

        self._btn = tk.Button(
            hdr, text="▶  Start", bg="#238636", fg="white",
            activebackground="#2ea043", activeforeground="white",
            relief="flat", font=("Segoe UI", 9, "bold"),
            padx=16, cursor="hand2", command=self._toggle,
        )
        self._btn.pack(side="left", padx=8, ipady=3)

        self._status_lbl = tk.Label(hdr, text="", bg=C["panel"], fg=C["dim"], font=UI)
        self._status_lbl.pack(side="left")

        # Dependency indicators (top-right)
        deps = []
        if HAS_REQ:    deps.append("requests ✓")
        else:          deps.append("requests ✗  (pip install requests)")
        if HAS_DNS:    deps.append("dnspython ✓")
        if HAS_WHOIS:  deps.append("python-whois ✓")
        tk.Label(hdr, text="  |  ".join(deps), bg=C["panel"], fg=C["dim"],
                 font=("Segoe UI", 7)).pack(side="right", padx=10)

    # ── Info panel ──────────────────────────────────────────────────────────────

    def _build_info_panel(self, parent):
        tk.Label(parent, text="NETWORK INFO", bg=C["panel"], fg=C["accent"],
                 font=UI_B).pack(anchor="w", padx=8, pady=(6, 4))

        cv = tk.Canvas(parent, bg=C["panel"], highlightthickness=0)
        sb = tk.Scrollbar(parent, orient="vertical", command=cv.yview)
        cv.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        cv.pack(fill="both", expand=True)

        self._info_frame = tk.Frame(cv, bg=C["panel"])
        win = cv.create_window((0, 0), window=self._info_frame, anchor="nw")

        self._info_frame.bind("<Configure>",
            lambda e: cv.configure(scrollregion=cv.bbox("all")))
        cv.bind("<Configure>",
            lambda e: cv.itemconfig(win, width=e.width))
        cv.bind("<MouseWheel>",
            lambda e: cv.yview_scroll(-1 * (e.delta // 120), "units"))

        self._info_texts = {}
        for key, title, hint_height in [
            ("dns",   "DNS Records",     6),
            ("geoip", "GeoIP / Location", 10),
            ("arin",  "ARIN / RDAP",     8),
            ("bgp",   "BGP Routing",     6),
            ("whois", "WHOIS",           12),
        ]:
            self._add_info_section(key, title, hint_height)

    def _add_info_section(self, key, title, hint_height=6):
        hf = tk.Frame(self._info_frame, bg=C["panel"])
        hf.pack(fill="x", padx=6, pady=(10, 2))
        tk.Label(hf, text=title.upper(), bg=C["panel"], fg=C["accent"],
                 font=("Segoe UI", 8, "bold")).pack(side="left")
        tk.Frame(hf, bg=C["border"], height=1).pack(
            side="left", fill="x", expand=True, padx=(6, 0))

        t = tk.Text(
            self._info_frame, bg=C["widget"], fg=C["fg"],
            font=MONO_SM, relief="flat", height=hint_height,
            wrap="word", state="disabled",
            selectbackground=C["accent"], selectforeground="white",
        )
        t.pack(fill="x", padx=6, pady=(0, 2))

        cf = tk.Frame(self._info_frame, bg=C["panel"])
        cf.pack(fill="x", padx=6, pady=(0, 2))
        tk.Button(
            cf, text="Copy", bg=C["widget"], fg=C["dim"],
            activebackground=C["border"], activeforeground=C["fg"],
            relief="flat", font=("Segoe UI", 7), padx=8, cursor="hand2",
            command=lambda w=t: self._copy_text(w),
        ).pack(side="right")

        self._info_texts[key] = t

    # ── MTR panel ───────────────────────────────────────────────────────────────

    def _build_mtr(self, parent):
        hf = tk.Frame(parent, bg=C["panel"])
        hf.pack(fill="x", padx=6, pady=(6, 3))
        tk.Label(hf, text="LIVE TRACEROUTE", bg=C["panel"], fg=C["accent"],
                 font=UI_B).pack(side="left")
        tk.Label(hf, text="  MTR-style · each hop probed continuously",
                 bg=C["panel"], fg=C["dim"], font=("Segoe UI", 8)).pack(side="left")

        # Legend
        for color, label in [(C["green"],"0% loss"), (C["yellow"],"<20% loss"),
                              (C["red"],">20% loss"), (C["dim"],"no response"),
                              (C["accent"],"destination")]:
            tk.Label(hf, text=f"  ■ {label}", bg=C["panel"], fg=color,
                     font=("Segoe UI", 7)).pack(side="right")

        cols   = ["hop","host","ip","loss","snt","rcv","last","avg","best","wrst","stdev"]
        hdrs   = ["#","Hostname","IP Address","Loss%","Snt","Rcv","Last ms","Avg ms","Best ms","Wrst ms","StDev"]
        widths = [28, 195, 125, 58, 42, 42, 64, 64, 64, 64, 64]

        frm = tk.Frame(parent, bg=C["panel"])
        frm.pack(fill="both", expand=True, padx=6, pady=(0, 6))

        self._tree = ttk.Treeview(frm, columns=cols, show="headings")
        vsb = ttk.Scrollbar(frm, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._tree.pack(fill="both", expand=True)

        for col, hdr, w in zip(cols, hdrs, widths):
            anchor = "w" if col in ("host", "ip") else "e"
            self._tree.heading(col, text=hdr, anchor=anchor)
            self._tree.column(col, width=w, minwidth=w, anchor=anchor, stretch=col == "host")

        self._tree.tag_configure("good",  foreground=C["green"])
        self._tree.tag_configure("warn",  foreground=C["yellow"])
        self._tree.tag_configure("bad",   foreground=C["red"])
        self._tree.tag_configure("star",  foreground=C["dim"])
        self._tree.tag_configure("dest",  foreground=C["accent"])
        self._tree.tag_configure("altbg", background="#1c2128")

    # ── Ping panel ──────────────────────────────────────────────────────────────

    def _build_ping(self, parent):
        hf = tk.Frame(parent, bg=C["panel"])
        hf.pack(fill="x", padx=6, pady=(6, 4))
        tk.Label(hf, text="PING MONITOR", bg=C["panel"], fg=C["accent"],
                 font=UI_B).pack(side="left")

        # Stats bar
        sf = tk.Frame(parent, bg=C["panel"])
        sf.pack(fill="x", padx=6, pady=(0, 4))

        self._ping_vars = {}
        for label in ["Sent", "Recv", "Loss%", "Last", "Avg", "Best", "Worst", "StDev"]:
            f = tk.Frame(sf, bg=C["widget"], padx=10, pady=4)
            f.pack(side="left", padx=(0, 3))
            tk.Label(f, text=label, bg=C["widget"], fg=C["dim"],
                     font=("Segoe UI", 7)).grid(row=0, column=0, sticky="w")
            var = tk.StringVar(value="—")
            self._ping_vars[label] = var
            tk.Label(f, textvariable=var, bg=C["widget"], fg=C["green"],
                     font=("Consolas", 10, "bold")).grid(row=1, column=0, sticky="w")

        # Log
        log_f = tk.Frame(parent, bg=C["panel"])
        log_f.pack(fill="both", expand=True, padx=6, pady=(0, 6))

        self._ping_log = tk.Text(
            log_f, bg=C["widget"], fg=C["fg"], font=MONO_SM,
            relief="flat", state="disabled", wrap="none",
        )
        vsb = tk.Scrollbar(log_f, orient="vertical", command=self._ping_log.yview)
        hsb = tk.Scrollbar(log_f, orient="horizontal", command=self._ping_log.xview)
        self._ping_log.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        self._ping_log.pack(fill="both", expand=True)

        self._ping_log.tag_configure("ts",      foreground=C["dim"])
        self._ping_log.tag_configure("ok",      foreground=C["green"])
        self._ping_log.tag_configure("timeout", foreground=C["red"])
        self._ping_log.tag_configure("slow",    foreground=C["yellow"])

    # ── Style ───────────────────────────────────────────────────────────────────

    def _apply_style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure("Treeview",
            background=C["panel"], foreground=C["fg"],
            fieldbackground=C["panel"], rowheight=22, font=MONO)
        s.configure("Treeview.Heading",
            background=C["widget"], foreground=C["accent"],
            font=("Segoe UI", 8, "bold"), relief="flat")
        s.map("Treeview",
            background=[("selected", "#1f6feb")],
            foreground=[("selected", "#ffffff")])
        s.configure("Vertical.TScrollbar",
            background=C["widget"], troughcolor=C["panel"],
            bordercolor=C["border"], arrowcolor=C["dim"])
        s.configure("Horizontal.TScrollbar",
            background=C["widget"], troughcolor=C["panel"],
            bordercolor=C["border"], arrowcolor=C["dim"])

    # ── Control ─────────────────────────────────────────────────────────────────

    def _toggle(self):
        if self._running:
            self._stop()
        else:
            self._start()

    def _start(self):
        target = self._target_var.get().strip()
        if not target:
            return

        self._running = True
        self._btn.configure(text="■  Stop", bg="#6e1f1f", activebackground="#a12626")
        self._status_lbl.configure(text=f"  ● Running → {target}", fg=C["green"])
        self._clear()

        self._mtr    = MTR(target,    lambda snap:  self.after(0, self._on_mtr,  snap))
        self._pinger = Pinger(target, lambda stats: self.after(0, self._on_ping, stats))
        self._lookup = Lookup(target, lambda r:     self.after(0, self._on_info, r))

        self._mtr.start()
        self._pinger.start()
        self._lookup.start()

    def _stop(self):
        self._running = False
        if self._mtr:    self._mtr.stop()
        if self._pinger: self._pinger.stop()
        self._btn.configure(text="▶  Start", bg="#238636", activebackground="#2ea043")
        self._status_lbl.configure(text="  Stopped", fg=C["dim"])

    def _clear(self):
        for item in self._tree.get_children():
            self._tree.delete(item)
        for t in self._info_texts.values():
            t.configure(state="normal")
            t.delete("1.0", "end")
            t.configure(state="disabled")
        for var in self._ping_vars.values():
            var.set("—")
        self._ping_log.configure(state="normal")
        self._ping_log.delete("1.0", "end")
        self._ping_log.configure(state="disabled")

    # ── Callbacks ───────────────────────────────────────────────────────────────

    def _on_mtr(self, snap):
        existing = {
            int(self._tree.set(item, "hop")): item
            for item in self._tree.get_children()
        }

        for n in sorted(snap.keys()):
            h = snap[n]
            display = h.host if h.host else (h.ip or "???")

            loss = h.loss
            if not h.ip:
                tag = "star"
            elif self._mtr and h.ip == self._mtr._target_ip:
                tag = "dest"
            elif loss == 0:
                tag = "good"
            elif loss < 20:
                tag = "warn"
            else:
                tag = "bad"

            row = (
                str(n), display, h.ip or "* * *",
                f"{loss:.1f}%", str(h.sent), str(h.recv),
                h.ms(h.last), h.ms(h.avg),
                h.ms(h.best), h.ms(h.worst), h.ms(h.stdev),
            )

            tags = (tag, "altbg") if n % 2 == 0 else (tag,)

            if n in existing:
                for col, val in zip(
                    ["hop","host","ip","loss","snt","rcv","last","avg","best","wrst","stdev"],
                    row
                ):
                    self._tree.set(existing[n], col, val)
                self._tree.item(existing[n], tags=tags)
            else:
                self._tree.insert("", "end", values=row, tags=tags)

    def _on_ping(self, stats):
        def ms(v):
            return f"{v:.1f}ms" if v is not None else "—"

        self._ping_vars["Sent"].set(str(stats["sent"]))
        self._ping_vars["Recv"].set(str(stats["recv"]))
        self._ping_vars["Loss%"].set(f"{stats['loss']:.1f}%")
        self._ping_vars["Last"].set(ms(stats["last"]))
        self._ping_vars["Avg"].set(ms(stats["avg"]))
        self._ping_vars["Best"].set(ms(stats["best"]))
        self._ping_vars["Worst"].set(ms(stats["worst"]))
        self._ping_vars["StDev"].set(ms(stats["stdev"]))

        # Color the loss stat
        loss = stats["loss"]
        color = C["green"] if loss == 0 else (C["yellow"] if loss < 5 else C["red"])
        # We can't easily change one label's color in the stat bar after creation,
        # so we rely on the log coloring for visual feedback.

        entry = stats.get("latest")
        if entry:
            ts, rtt, ip = entry
            self._ping_log.configure(state="normal")
            self._ping_log.insert("end", f"[{ts}]  ", "ts")
            avg = stats["avg"]
            if rtt is not None:
                tag = "slow" if (avg and rtt > avg * 1.8) else "ok"
                self._ping_log.insert("end", f"Reply from {ip}: {rtt}ms\n", tag)
            else:
                self._ping_log.insert("end", f"{ip}: Request timed out.\n", "timeout")
            self._ping_log.see("end")
            self._ping_log.configure(state="disabled")

    def _on_info(self, result):
        key  = result["section"]
        data = result["data"] or "No data"
        if key not in self._info_texts:
            return
        t = self._info_texts[key]
        t.configure(state="normal")
        t.delete("1.0", "end")
        t.insert("1.0", data)
        lines = data.count("\n") + 1
        t.configure(height=max(3, min(lines + 1, 30)), state="disabled")

    # ── Helpers ─────────────────────────────────────────────────────────────────

    def _copy_text(self, widget):
        text = widget.get("1.0", "end").strip()
        self.clipboard_clear()
        self.clipboard_append(text)

    def on_close(self):
        self._stop()
        self.destroy()


# ─── Entry point ───────────────────────────────────────────────────────────────
def main():
    app = CoolTR()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()


if __name__ == "__main__":
    main()
