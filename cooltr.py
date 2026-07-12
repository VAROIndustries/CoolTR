#!/usr/bin/env python3
"""
CoolTR — Cool TraceRoute
Windows network diagnostic: live MTR traceroute, continuous ping stats,
DNS, GeoIP, ARIN/RDAP, BGP, and WHOIS lookups in one dark-themed window.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import socket
import subprocess
import re
import time
import math
import os
import sqlite3
import json
import csv
import ssl as _ssl_mod
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


# ─── Theme ──────────────────────────────────────────────────────────────────────
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
MONO     = ("Consolas", 9)
MONO_SM  = ("Consolas", 8)
UI       = ("Segoe UI", 9)
UI_B     = ("Segoe UI", 9, "bold")

_APP_DIR     = os.path.dirname(os.path.abspath(__file__))
_DB_PATH     = os.path.join(_APP_DIR, "cooltr_history.db")
_SPARK_CHARS = " ▁▂▃▄▅▆▇█"


# ─── SQLite ──────────────────────────────────────────────────────────────────────
def _db_init():
    try:
        con = sqlite3.connect(_DB_PATH)
        con.execute("""CREATE TABLE IF NOT EXISTS runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, target TEXT, duration_s REAL)""")
        con.execute("""CREATE TABLE IF NOT EXISTS hops (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER, n INTEGER, ip TEXT, host TEXT,
            loss REAL, avg_ms REAL, best_ms REAL, worst_ms REAL, sent INTEGER)""")
        con.commit()
        con.close()
    except Exception:
        pass


def _db_save_run(target, duration_s, hops_data):
    try:
        con = sqlite3.connect(_DB_PATH)
        ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cur = con.execute(
            "INSERT INTO runs (ts,target,duration_s) VALUES (?,?,?)",
            (ts, target, duration_s))
        run_id = cur.lastrowid
        for h in hops_data:
            con.execute(
                "INSERT INTO hops (run_id,n,ip,host,loss,avg_ms,best_ms,worst_ms,sent) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (run_id, h["n"], h["ip"], h["host"],
                 h.get("loss"), h.get("avg"), h.get("best"), h.get("worst"), h.get("sent")))
        con.commit()
        con.close()
    except Exception:
        pass


def _db_load_runs(limit=100):
    try:
        con = sqlite3.connect(_DB_PATH)
        rows = con.execute(
            "SELECT id,ts,target,duration_s FROM runs ORDER BY id DESC LIMIT ?",
            (limit,)).fetchall()
        con.close()
        return rows
    except Exception:
        return []


def _db_load_hops(run_id):
    try:
        con = sqlite3.connect(_DB_PATH)
        rows = con.execute(
            "SELECT n,ip,host,loss,avg_ms,best_ms,worst_ms,sent FROM hops "
            "WHERE run_id=? ORDER BY n", (run_id,)).fetchall()
        con.close()
        return rows
    except Exception:
        return []


def _db_get_targets(limit=50):
    try:
        con  = sqlite3.connect(_DB_PATH)
        rows = con.execute(
            "SELECT DISTINCT target FROM runs ORDER BY id DESC LIMIT ?",
            (limit,)).fetchall()
        con.close()
        return [r[0] for r in rows]
    except Exception:
        return []


# ─── Sparkline ───────────────────────────────────────────────────────────────────
def _sparkline(rtts, width=14):
    vals = list(rtts)[-width:]
    if not vals:
        return "─" * width
    lo, hi = min(vals), max(vals)
    if lo == hi:
        bar = "▄" * len(vals)
    else:
        bar = "".join(
            _SPARK_CHARS[min(int((v - lo) / (hi - lo) * 8), 8)]
            for v in vals)
    return bar.ljust(width)


# ─── System ping ─────────────────────────────────────────────────────────────────
def _ping(host, ttl=None, timeout_ms=2000):
    cmd = ["ping", "-n", "1", "-w", str(timeout_ms)]
    if ttl is not None:
        cmd += ["-i", str(ttl)]
    cmd.append(host)
    try:
        out = subprocess.check_output(
            cmd, stderr=subprocess.DEVNULL,
            timeout=(timeout_ms / 1000) + 3,
            creationflags=subprocess.CREATE_NO_WINDOW,
        ).decode(errors="replace")
    except Exception:
        return None, None, False
    ip_m    = re.search(r"Reply from ([\d.]+)", out)
    rtt_m   = re.search(r"time[<=>]+(\d+)ms", out)
    expired = "TTL expired" in out or "TTL Expired" in out
    ip  = ip_m.group(1) if ip_m else None
    rtt = int(rtt_m.group(1)) if rtt_m else (0 if ip and "time<" in out else None)
    return ip, rtt, expired


# ─── Hop ─────────────────────────────────────────────────────────────────────────
class Hop:
    def __init__(self, n):
        self.n     = n
        self.ip    = ""
        self.host  = ""
        self.sent  = 0
        self.recv  = 0
        self.last  = None
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
        if len(d) < 2: return None
        a = sum(d) / len(d)
        return math.sqrt(sum((x - a) ** 2 for x in d) / len(d))

    @property
    def spark(self):
        return _sparkline(self._rtts)

    @staticmethod
    def ms(v, dec=1):
        return f"{v:.{dec}f}" if v is not None else "—"


# ─── MTR Engine ──────────────────────────────────────────────────────────────────
class MTR:
    def __init__(self, target, callback, on_new_ip=None, force_ipv6=False):
        self.target          = target
        self.cb              = callback
        self.on_new_ip       = on_new_ip
        self._force_ipv6     = force_ipv6
        self.hops            = {}
        self.running         = False
        self._lock           = threading.Lock()
        self._target_ip      = ""
        self._max_ttl        = 0
        self._rcache         = {}
        self._started_probes = set()

    def start(self):
        self.running = True
        try:
            af = socket.AF_INET6 if self._force_ipv6 else socket.AF_INET
            self._target_ip = socket.getaddrinfo(self.target, None, af)[0][4][0]
        except Exception:
            self._target_ip = self.target
        threading.Thread(target=self._discover, daemon=True).start()
        threading.Thread(target=self._ui_clock,  daemon=True).start()

    def stop(self):
        self.running = False

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

    def _notify_ip(self, ip):
        if self.on_new_ip and ip:
            self.on_new_ip(ip)

    def _discover(self):
        try:
            cmd = ["tracert", "-d", "-w", "1500", "-h", "30"]
            if self._force_ipv6:
                cmd.append("-6")
            cmd.append(self.target)
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            for raw in proc.stdout:
                if not self.running:
                    proc.terminate(); return
                line = raw.decode(errors="replace")
                m = re.match(r"\s*(\d+)\s+", line)
                if not m: continue
                ttl = int(m.group(1))
                hop = self._get_hop(ttl)
                with self._lock:
                    self._max_ttl = max(self._max_ttl, ttl)
                ips = re.findall(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
                if ips:
                    ip_val = ips[-1]
                    with self._lock:
                        hop.ip = ip_val
                    threading.Thread(
                        target=lambda h=hop, ip=ip_val: setattr(h, "host", self._resolve(ip)),
                        daemon=True).start()
                    self._notify_ip(ip_val)
                self._ensure_probe(ttl)
            proc.wait()
        except Exception:
            pass
        if self._max_ttl == 0:
            self._max_ttl = 30
            for ttl in range(1, 31):
                self._ensure_probe(ttl)

    def _probe_loop(self, ttl):
        while self.running:
            t0  = time.time()
            hop = self._get_hop(ttl)
            with self._lock:
                hop.sent += 1
            ip, rtt, _ = _ping(self.target, ttl=ttl, timeout_ms=2000)
            if ip:
                with self._lock:
                    if ip != hop.ip:
                        hop.ip   = ip
                        hop.host = ""
                    if not hop.host:
                        ip_copy = ip
                        threading.Thread(
                            target=lambda h=hop, i=ip_copy: setattr(h, "host", self._resolve(i)),
                            daemon=True).start()
                self._notify_ip(ip)
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


# ─── Pinger ──────────────────────────────────────────────────────────────────────
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


# ─── Lookup ──────────────────────────────────────────────────────────────────────
class Lookup:
    def __init__(self, target, callback, force_ipv6=False, features=None):
        self.target      = target
        self.cb          = callback
        self._force_ipv6 = force_ipv6
        self._features   = features or {}

    def start(self):
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        f = self._features
        self.cb({"section": "dns", "data": self._dns()})
        if f.get("dns_multi", True):
            self.cb({"section": "dns_multi", "data": self._dns_multi()})
        else:
            self.cb({"section": "dns_multi", "data": "disabled"})
        if HAS_REQ:
            for key, method in [
                ("geoip", self._geoip),
                ("arin",  self._arin),
                ("bgp",   self._bgp),
                ("http",  self._http),
            ]:
                if f.get(key, True):
                    self.cb({"section": key, "data": method()})
                else:
                    self.cb({"section": key, "data": "disabled"})
        else:
            for s in ("geoip", "arin", "bgp", "http"):
                self.cb({"section": s, "data": "pip install requests to enable"})
        self.cb({"section": "ssl",
                 "data": self._ssl() if f.get("ssl", True) else "disabled"})
        self.cb({"section": "ports",
                 "data": self._ports() if f.get("ports", False) else "disabled (enable in ⚙ Settings)"})
        self.cb({"section": "whois",
                 "data": self._whois() if f.get("whois", True) else "disabled"})

    def _resolve_ip(self):
        try:
            af = socket.AF_INET6 if self._force_ipv6 else socket.AF_INET
            return socket.getaddrinfo(self.target, None, af)[0][4][0]
        except Exception:
            return self.target

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
            lines.append("(install dnspython for full DNS records)")
        return "\n".join(lines)

    def _geoip(self):
        ip = self._resolve_ip()
        try:
            d = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,"
                "regionName,city,zip,lat,lon,timezone,isp,org,as,query",
                timeout=5).json()
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

    def _arin(self):
        ip = self._resolve_ip()
        try:
            d = requests.get(
                f"https://rdap.arin.net/registry/ip/{ip}",
                timeout=6, headers={"Accept": "application/json"}).json()
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
                fn    = next((v[3] for v in vcard if v[0] == "fn"), "")
                email = next((v[3] for v in vcard if v[0] == "email"), "")
                if fn:
                    lbl = "/".join(roles)[:8]
                    lines.append(f"{lbl:8}: {fn}" + (f" <{email}>" if email else ""))
            for rem in d.get("remarks", [])[:2]:
                desc = rem.get("description", [])
                if desc:
                    lines.append(f"{'Note':8}: {desc[0][:60]}")
            return "\n".join(lines) if lines else "No ARIN data"
        except Exception as e:
            return f"Error: {e}"

    def _bgp(self):
        ip = self._resolve_ip()
        # Primary: RIPE Stat (free, no auth)
        try:
            d = requests.get(
                f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}",
                timeout=8).json()
            if d.get("status") == "ok":
                data  = d.get("data", {})
                lines = []
                for pfx in data.get("prefixes", [])[:4]:
                    lines.append(f"Prefix : {pfx.get('prefix','')}")
                    desc = pfx.get("description") or pfx.get("name", "")
                    if desc:
                        lines.append(f"  Desc : {desc}")
                    for a in pfx.get("origin_asns", [])[:2]:
                        lines.append(f"  ASN  : AS{a.get('asn','')}  {a.get('holder','')}")
                if not lines:
                    for a in data.get("asns", [])[:4]:
                        lines.append(f"ASN    : AS{a.get('asn','')}  {a.get('holder','')}")
                if lines:
                    lines.insert(0, "[RIPE Stat]")
                    return "\n".join(lines)
        except Exception:
            pass
        # Fallback: ipinfo.io (free tier, no auth)
        try:
            d = requests.get(f"https://ipinfo.io/{ip}/json", timeout=8).json()
            lines = ["[ipinfo.io]"]
            if "org" in d:
                lines.append(f"ASN    : {d['org']}")
            if "country" in d:
                lines.append(f"CC     : {d['country']}")
            if len(lines) > 1:
                return "\n".join(lines)
        except Exception:
            pass
        return "No BGP data"

    def _ssl(self):
        host = re.sub(r"^https?://", "", self.target).split("/")[0].split(":")[0]
        try:
            ctx = _ssl_mod.create_default_context()
            with socket.create_connection((host, 443), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert   = ssock.getpeercert()
                    cipher = ssock.cipher()
            subject  = dict(x[0] for x in cert.get("subject",  []))
            issuer   = dict(x[0] for x in cert.get("issuer",   []))
            not_after = cert.get("notAfter", "")
            lines = [
                f"{'CN':8}: {subject.get('commonName', '')}",
                f"{'Issuer':8}: {issuer.get('organizationName', issuer.get('commonName',''))}",
                f"{'Expires':8}: {not_after}",
            ]
            if not_after:
                try:
                    exp  = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days = (exp - datetime.utcnow()).days
                    note = "  ⚠ EXPIRING SOON" if 0 < days < 30 else ("  ✗ EXPIRED" if days <= 0 else "")
                    lines.append(f"{'Days left':8}: {days}{note}")
                except Exception:
                    pass
            sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
            if sans:
                lines.append(f"{'SANs':8}: {', '.join(sans[:8])}")
            if cipher:
                lines.append(f"{'Cipher':8}: {cipher[0]}")
                lines.append(f"{'TLS ver':8}: {cipher[1]}")
            return "\n".join(lines)
        except _ssl_mod.SSLCertVerificationError as e:
            return f"Cert verify error: {e}"
        except ConnectionRefusedError:
            return "Port 443 not open"
        except Exception as e:
            return f"Error: {e}"

    def _dns_multi(self):
        if not HAS_DNS:
            return "(install dnspython for multi-resolver check)"
        resolvers = [
            ("Cloudflare", "1.1.1.1"),
            ("Google",     "8.8.8.8"),
            ("Quad9",      "9.9.9.9"),
            ("OpenDNS",    "208.67.222.222"),
        ]
        lines = []
        for name, ns in resolvers:
            try:
                r = _dns_resolver.Resolver()
                r.nameservers = [ns]
                r.lifetime = 4
                ans = r.resolve(self.target, "A")
                ips = [str(a) for a in ans]
                lines.append(f"{name:<12} {ns:<17} {', '.join(ips)}")
            except Exception as e:
                lines.append(f"{name:<12} {ns:<17} Error: {e}")
        return "\n".join(lines)

    def _ports(self):
        ip = self._resolve_ip()
        COMMON = [
            (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"),
            (53, "DNS"), (80, "HTTP"), (110, "POP3"), (143, "IMAP"),
            (443, "HTTPS"), (445, "SMB"), (587, "SMTP/S"), (993, "IMAPS"),
            (3306, "MySQL"), (3389, "RDP"), (5432, "Postgres"),
            (6379, "Redis"), (8080, "HTTP-alt"), (8443, "HTTPS-alt"),
        ]
        results = {}
        def _chk(port):
            try:
                s = socket.socket()
                s.settimeout(1.5)
                results[port] = s.connect_ex((ip, port)) == 0
                s.close()
            except Exception:
                results[port] = False
        threads = [threading.Thread(target=_chk, args=(p,), daemon=True) for p, _ in COMMON]
        for t in threads: t.start()
        for t in threads: t.join(timeout=3)
        open_p   = [(p, n) for p, n in COMMON if results.get(p)]
        closed_p = [(p, n) for p, n in COMMON if not results.get(p)]
        lines = []
        if open_p:
            lines.append("OPEN:")
            for p, n in open_p:
                lines.append(f"  {p:<6} {n}")
        if closed_p:
            lines.append("CLOSED / FILTERED:")
            for p, n in closed_p:
                lines.append(f"  {p:<6} {n}")
        return "\n".join(lines) if lines else "No data"

    def _http(self):
        if not HAS_REQ:
            return "pip install requests to enable"
        url = self.target
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        try:
            resp  = requests.get(url, timeout=10, allow_redirects=True,
                                 headers={"User-Agent": "CoolTR/1.0"})
            chain = resp.history + [resp]
            lines = []
            for i, r in enumerate(chain):
                sym = "→" if i < len(chain) - 1 else "✓"
                lines.append(f"{sym} [{r.status_code}] {r.url[:72]}")
            lines += [
                f"{'Server':8}: {resp.headers.get('Server', '')}",
                f"{'Type':8}: {resp.headers.get('Content-Type', '')[:50]}",
                f"{'Size':8}: {len(resp.content):,} bytes",
            ]
            for hdr in ("Strict-Transport-Security", "X-Frame-Options",
                        "Content-Security-Policy", "X-Content-Type-Options"):
                val = resp.headers.get(hdr, "")
                if val:
                    lines.append(f"{hdr[:8]:8}: {val[:60]}")
            return "\n".join(lines)
        except Exception as e:
            if url.startswith("https://"):
                try:
                    resp = requests.get("http://" + url[8:], timeout=8,
                                        allow_redirects=True,
                                        headers={"User-Agent": "CoolTR/1.0"})
                    return f"[HTTP fallback]\n✓ [{resp.status_code}] {resp.url[:72]}"
                except Exception:
                    pass
            return f"Error: {e}"

    def _whois(self):
        if HAS_WHOIS:
            try:
                w = _pywhois.whois(self.target)
                lines = [l for l in str(w).split("\n") if l.strip()]
                return "\n".join(lines[:100])
            except Exception as e:
                return f"Error: {e}"
        try:
            out = subprocess.check_output(
                ["whois", self.target], stderr=subprocess.DEVNULL,
                timeout=10, creationflags=subprocess.CREATE_NO_WINDOW,
            ).decode(errors="replace")
            lines = [l for l in out.split("\n")
                     if l.strip() and not l.startswith(("%", "#", ";"))]
            return "\n".join(lines[:100])
        except Exception as e:
            return f"WHOIS unavailable: {e}\n(pip install python-whois)"


# ─── GeoIP cache (shared across tabs) ───────────────────────────────────────────
class GeoCache:
    def __init__(self):
        self._data     = {}
        self._fetching = set()
        self._lock     = threading.Lock()

    def get(self, ip):
        with self._lock:
            return self._data.get(ip)

    def fetch_if_needed(self, ip):
        if not HAS_REQ or not ip:
            return
        with self._lock:
            if ip in self._data or ip in self._fetching:
                return
            self._fetching.add(ip)
        threading.Thread(target=self._fetch, args=(ip,), daemon=True).start()

    def _fetch(self, ip):
        try:
            d = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,as,isp",
                timeout=5).json()
            if d.get("status") == "success":
                with self._lock:
                    self._data[ip] = {
                        "lat":     float(d.get("lat", 0)),
                        "lon":     float(d.get("lon", 0)),
                        "country": d.get("country", ""),
                        "cc":      d.get("countryCode", ""),
                        "city":    d.get("city", ""),
                        "asn":     d.get("as", ""),
                        "isp":     d.get("isp", ""),
                    }
        except Exception:
            pass
        finally:
            with self._lock:
                self._fetching.discard(ip)


# ─── History viewer ──────────────────────────────────────────────────────────────
class HistoryViewer(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("CoolTR — Run History")
        self.geometry("860x480")
        self.configure(bg=C["bg"])
        self._build()
        self._load_runs()

    def _build(self):
        top = tk.Frame(self, bg=C["bg"])
        top.pack(fill="both", expand=True, padx=8, pady=8)

        runs_f = tk.Frame(top, bg=C["panel"])
        runs_f.pack(side="left", fill="y", padx=(0, 4))
        tk.Label(runs_f, text="PAST RUNS", bg=C["panel"], fg=C["accent"],
                 font=UI_B).pack(anchor="w", padx=6, pady=(6, 3))
        cols = ["ts", "target", "dur"]
        self._runs_tree = ttk.Treeview(runs_f, columns=cols, show="headings", height=18)
        for col, hdr, w in zip(cols, ["Time", "Target", "Dur"], [140, 190, 60]):
            self._runs_tree.heading(col, text=hdr, anchor="w")
            self._runs_tree.column(col, width=w, anchor="w")
        self._runs_tree.pack(fill="both", expand=True, padx=4, pady=(0, 4))
        self._runs_tree.bind("<<TreeviewSelect>>", self._on_select)

        detail_f = tk.Frame(top, bg=C["panel"])
        detail_f.pack(side="left", fill="both", expand=True)
        tk.Label(detail_f, text="HOP DETAILS", bg=C["panel"], fg=C["accent"],
                 font=UI_B).pack(anchor="w", padx=6, pady=(6, 3))
        hcols  = ["n", "ip", "host", "loss", "avg", "best", "worst", "sent"]
        hhdrs  = ["#", "IP", "Hostname", "Loss%", "Avg ms", "Best", "Worst", "Sent"]
        hwids  = [30, 120, 185, 55, 65, 55, 55, 45]
        self._hops_tree = ttk.Treeview(detail_f, columns=hcols, show="headings", height=18)
        for col, hdr, w in zip(hcols, hhdrs, hwids):
            self._hops_tree.heading(col, text=hdr, anchor="w")
            self._hops_tree.column(col, width=w, anchor="w")
        self._hops_tree.pack(fill="both", expand=True, padx=4, pady=(0, 4))

    def _load_runs(self):
        for item in self._runs_tree.get_children():
            self._runs_tree.delete(item)
        for run_id, ts, target, dur in _db_load_runs():
            self._runs_tree.insert("", "end", iid=str(run_id),
                                   values=(ts, target, f"{dur:.0f}s" if dur else "?"))

    def _on_select(self, _e):
        sel = self._runs_tree.selection()
        if not sel:
            return
        for item in self._hops_tree.get_children():
            self._hops_tree.delete(item)
        for n, ip, host, loss, avg, best, worst, sent in _db_load_hops(int(sel[0])):
            def _ms(v): return f"{v:.1f}" if v is not None else "—"
            self._hops_tree.insert("", "end", values=(
                n, ip or "* * *", host or "",
                f"{loss:.1f}%" if loss is not None else "—",
                _ms(avg), _ms(best), _ms(worst), sent or 0))


# ─── Settings popup ───────────────────────────────────────────────────────────────
class ThresholdConfig(tk.Toplevel):
    def __init__(self, master, session):
        super().__init__(master)
        self.title("Settings")
        self.geometry("290x390")
        self.resizable(False, False)
        self.configure(bg=C["bg"])
        self._session = session
        self._build()

    def _build(self):
        outer = tk.Frame(self, bg=C["bg"], padx=16, pady=14)
        outer.pack(fill="both", expand=True)

        # ── Alert thresholds ────────────────────────────────────────────────────
        tk.Label(outer, text="ALERT THRESHOLDS", bg=C["bg"], fg=C["accent"],
                 font=("Segoe UI", 8, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 6))
        self._thresh_vars = {}
        for i, (label, attr, unit) in enumerate([
            ("Loss alert",    "_thresh_loss", "%"),
            ("Avg RTT alert", "_thresh_ms",   "ms"),
        ], start=1):
            tk.Label(outer, text=label, bg=C["bg"], fg=C["fg"], font=UI).grid(
                row=i, column=0, sticky="w", pady=4)
            var = tk.StringVar(value=str(getattr(self._session, attr)))
            self._thresh_vars[attr] = var
            tk.Entry(outer, textvariable=var, bg=C["widget"], fg=C["fg"],
                     insertbackground=C["fg"], relief="flat", bd=4,
                     font=MONO, width=8).grid(row=i, column=1, padx=8)
            tk.Label(outer, text=unit, bg=C["bg"], fg=C["dim"], font=UI).grid(
                row=i, column=2, sticky="w")

        # ── Divider ──────────────────────────────────────────────────────────────
        tk.Frame(outer, bg=C["border"], height=1).grid(
            row=3, column=0, columnspan=3, sticky="ew", pady=(12, 8))

        # ── Feature toggles ──────────────────────────────────────────────────────
        tk.Label(outer, text="LOOKUP FEATURES", bg=C["bg"], fg=C["accent"],
                 font=("Segoe UI", 8, "bold")).grid(
            row=4, column=0, columnspan=3, sticky="w", pady=(0, 4))

        self._feat_vars = {}
        feat_rows = [
            ("dns_multi", "DNS Propagation",  True),
            ("http",      "HTTP Probe",       True),
            ("ssl",       "SSL Certificate",  True),
            ("arin",      "ARIN / RDAP",      True),
            ("bgp",       "BGP Routing",      True),
            ("whois",     "WHOIS",            True),
            ("ports",     "Port Scan",        False),
        ]
        for i, (key, label, _default) in enumerate(feat_rows, start=5):
            var = tk.BooleanVar(value=self._session._features.get(key, _default))
            self._feat_vars[key] = var
            cb = tk.Checkbutton(
                outer, text=label, variable=var,
                bg=C["bg"], fg=C["fg"], selectcolor=C["widget"],
                activebackground=C["bg"], activeforeground=C["fg"],
                font=UI, anchor="w", cursor="hand2")
            cb.grid(row=i, column=0, columnspan=3, sticky="w", pady=1)

        # ── Save button ──────────────────────────────────────────────────────────
        tk.Button(outer, text="Save", bg=C["accent"], fg="white",
                  activebackground="#1158c7", relief="flat", font=UI_B,
                  padx=16, cursor="hand2", command=self._save).grid(
            row=5 + len(feat_rows), column=0, columnspan=3,
            pady=(10, 0), sticky="ew")

    def _save(self):
        for attr, var in self._thresh_vars.items():
            try:
                setattr(self._session, attr, float(var.get()))
            except ValueError:
                pass
        for key, var in self._feat_vars.items():
            self._session._features[key] = var.get()
        self.destroy()


# ─── Session Tab ─────────────────────────────────────────────────────────────────
class SessionTab:
    """One complete trace session — all UI lives inside self.frame."""

    def __init__(self, notebook, app, geo_cache):
        self._app      = app
        self._geo      = geo_cache
        self._mtr      = None
        self._pinger   = None
        self._lookup   = None
        self._running  = False
        self._start_ts = None

        self._thresh_loss = 20.0
        self._thresh_ms   = 200.0
        self._alerted     = set()
        self._ipv6        = False
        self._rtt_history = deque(maxlen=120)
        self._features    = {
            "dns_multi": True,
            "geoip":     True,
            "arin":      True,
            "bgp":       True,
            "http":      True,
            "ssl":       True,
            "ports":     False,   # off by default — intrusive
            "whois":     True,
        }

        self._tooltip_win        = None
        self._last_tooltip_item  = None

        self.frame = tk.Frame(notebook, bg=C["bg"])
        self._build()

    # ── Build ────────────────────────────────────────────────────────────────────

    def _build(self):
        self._build_tab_header()
        body = tk.Frame(self.frame, bg=C["bg"])
        body.pack(fill="both", expand=True, padx=4, pady=(0, 4))

        left = tk.Frame(body, bg=C["panel"], width=300)
        left.pack(side="left", fill="y", padx=(0, 4))
        left.pack_propagate(False)
        self._build_info_panel(left)

        right = tk.Frame(body, bg=C["bg"])
        right.pack(side="left", fill="both", expand=True)

        mtr_f = tk.Frame(right, bg=C["panel"])
        mtr_f.pack(fill="both", expand=True, pady=(0, 4))
        self._build_mtr(mtr_f)

        ping_f = tk.Frame(right, bg=C["panel"], height=220)
        ping_f.pack(fill="x", pady=(0, 4))
        ping_f.pack_propagate(False)
        self._build_ping(ping_f)

        map_f = tk.Frame(right, bg=C["panel"], height=150)
        map_f.pack(fill="x")
        map_f.pack_propagate(False)
        self._build_map(map_f)

    def _build_tab_header(self):
        hdr = tk.Frame(self.frame, bg=C["panel"], height=44)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        tk.Label(hdr, text="Target:", bg=C["panel"], fg=C["dim"], font=UI).pack(
            side="left", padx=(10, 5))
        self._target_var = tk.StringVar()
        self._target = ttk.Combobox(
            hdr, textvariable=self._target_var,
            font=("Consolas", 11), width=28)
        self._target.pack(side="left", ipady=3)
        self._target.bind("<Return>", lambda e: self._toggle())
        self._target["postcommand"] = self._refresh_target_history

        self._btn = tk.Button(
            hdr, text="▶  Start", bg="#238636", fg="white",
            activebackground="#2ea043", activeforeground="white",
            relief="flat", font=("Segoe UI", 9, "bold"),
            padx=14, cursor="hand2", command=self._toggle)
        self._btn.pack(side="left", padx=(8, 4), ipady=3)

        self._ipv6_btn = tk.Button(
            hdr, text="IPv4", bg=C["widget"], fg=C["dim"],
            activebackground=C["border"], activeforeground=C["fg"],
            relief="flat", font=("Segoe UI", 8), padx=8,
            cursor="hand2", command=self._toggle_ipv6)
        self._ipv6_btn.pack(side="left", padx=(0, 4), ipady=3)

        self._status_lbl = tk.Label(hdr, text="", bg=C["panel"], fg=C["dim"], font=UI)
        self._status_lbl.pack(side="left", padx=(4, 0))

        for text, cmd in [("Export", self._export), ("⚙", self._open_thresholds)]:
            tk.Button(hdr, text=text, bg=C["widget"], fg=C["dim"],
                      activebackground=C["border"], activeforeground=C["fg"],
                      relief="flat", font=("Segoe UI", 8), padx=8,
                      cursor="hand2", command=cmd).pack(
                side="right", padx=(0, 4), ipady=2)

        tk.Button(hdr, text="× Close", bg=C["widget"], fg=C["dim"],
                  activebackground="#6e1f1f", activeforeground=C["fg"],
                  relief="flat", font=("Segoe UI", 8), padx=8,
                  cursor="hand2", command=self._close).pack(
            side="right", padx=(0, 0), ipady=2)

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
        cv.bind("<Configure>", lambda e: cv.itemconfig(win, width=e.width))
        cv.bind("<MouseWheel>",
            lambda e: cv.yview_scroll(-1 * (e.delta // 120), "units"))
        self._info_texts = {}
        for key, title, hint_h in [
            ("dns",      "DNS Records",        6),
            ("dns_multi","DNS Propagation",    5),
            ("geoip",    "GeoIP / Location",  10),
            ("arin",     "ARIN / RDAP",        8),
            ("bgp",      "BGP Routing",        6),
            ("http",     "HTTP Probe",         8),
            ("ssl",      "SSL Certificate",    7),
            ("ports",    "Port Scan",         10),
            ("alerts",   "Alert Log",          4),
            ("whois",    "WHOIS",             12),
        ]:
            self._add_info_section(key, title, hint_h)

    def _add_info_section(self, key, title, hint_height=6):
        hf = tk.Frame(self._info_frame, bg=C["panel"])
        hf.pack(fill="x", padx=6, pady=(10, 2))
        tk.Label(hf, text=title.upper(), bg=C["panel"], fg=C["accent"],
                 font=("Segoe UI", 8, "bold")).pack(side="left")
        tk.Frame(hf, bg=C["border"], height=1).pack(
            side="left", fill="x", expand=True, padx=(6, 0))
        t = tk.Text(self._info_frame, bg=C["widget"], fg=C["fg"],
                    font=MONO_SM, relief="flat", height=hint_height,
                    wrap="word", state="disabled",
                    selectbackground=C["accent"], selectforeground="white")
        t.pack(fill="x", padx=6, pady=(0, 2))
        cf = tk.Frame(self._info_frame, bg=C["panel"])
        cf.pack(fill="x", padx=6, pady=(0, 2))
        tk.Button(cf, text="Copy", bg=C["widget"], fg=C["dim"],
                  activebackground=C["border"], activeforeground=C["fg"],
                  relief="flat", font=("Segoe UI", 7), padx=8, cursor="hand2",
                  command=lambda w=t: self._copy_text(w)).pack(side="right")
        self._info_texts[key] = t

    def _build_mtr(self, parent):
        hf = tk.Frame(parent, bg=C["panel"])
        hf.pack(fill="x", padx=6, pady=(6, 3))
        tk.Label(hf, text="LIVE TRACEROUTE", bg=C["panel"], fg=C["accent"],
                 font=UI_B).pack(side="left")
        tk.Label(hf, text="  MTR-style · each hop probed continuously",
                 bg=C["panel"], fg=C["dim"], font=("Segoe UI", 8)).pack(side="left")
        for color, label in [(C["green"], "0% loss"), (C["yellow"], "<20% loss"),
                              (C["red"], ">20% loss"), (C["dim"], "no response"),
                              (C["accent"], "destination")]:
            tk.Label(hf, text=f"  ■ {label}", bg=C["panel"], fg=color,
                     font=("Segoe UI", 7)).pack(side="right")

        cols   = ["hop", "spark", "host", "ip", "loss", "snt", "rcv",
                  "last", "avg", "best", "wrst", "stdev"]
        hdrs   = ["#", "RTT History", "Hostname", "IP Address", "Loss%",
                  "Snt", "Rcv", "Last ms", "Avg ms", "Best ms", "Wrst ms", "StDev"]
        widths = [28, 102, 165, 120, 58, 42, 42, 64, 64, 64, 64, 64]

        frm = tk.Frame(parent, bg=C["panel"])
        frm.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        self._tree = ttk.Treeview(frm, columns=cols, show="headings")
        vsb = ttk.Scrollbar(frm, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._tree.pack(fill="both", expand=True)

        for col, hdr, w in zip(cols, hdrs, widths):
            anchor = "w" if col in ("host", "ip", "spark") else "e"
            self._tree.heading(col, text=hdr, anchor=anchor)
            self._tree.column(col, width=w, minwidth=w, anchor=anchor,
                               stretch=(col == "host"))

        self._tree.tag_configure("good",  foreground=C["green"])
        self._tree.tag_configure("warn",  foreground=C["yellow"])
        self._tree.tag_configure("bad",   foreground=C["red"])
        self._tree.tag_configure("star",  foreground=C["dim"])
        self._tree.tag_configure("dest",  foreground=C["accent"])
        self._tree.tag_configure("altbg", background="#1c2128")

        self._tree.bind("<Motion>",   self._on_tree_motion)
        self._tree.bind("<Leave>",    lambda e: self._hide_tooltip())
        self._tree.bind("<Button-3>", self._on_tree_right_click)

    def _build_ping(self, parent):
        hf = tk.Frame(parent, bg=C["panel"])
        hf.pack(fill="x", padx=6, pady=(6, 4))
        tk.Label(hf, text="PING MONITOR", bg=C["panel"], fg=C["accent"],
                 font=UI_B).pack(side="left")
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
        # RTT graph canvas
        self._rtt_canvas = tk.Canvas(parent, bg=C["widget"], height=58,
                                      highlightthickness=0)
        self._rtt_canvas.pack(fill="x", padx=6, pady=(0, 2))
        self._rtt_canvas.bind("<Configure>", lambda e: self._redraw_rtt_graph())

        log_f = tk.Frame(parent, bg=C["panel"])
        log_f.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        self._ping_log = tk.Text(log_f, bg=C["widget"], fg=C["fg"], font=MONO_SM,
                                  relief="flat", state="disabled", wrap="none")
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

    def _redraw_rtt_graph(self):
        cv = self._rtt_canvas
        w  = cv.winfo_width()
        h  = cv.winfo_height()
        if w < 10 or h < 10:
            return
        cv.delete("all")
        cv.create_rectangle(0, 0, w, h, fill=C["widget"], outline="")
        hist = list(self._rtt_history)
        timeouts = [v is None for v in hist]
        vals = [v if v is not None else 0 for v in hist]
        if not vals:
            cv.create_text(w // 2, h // 2, text="waiting for ping data…",
                           fill=C["dim"], font=("Segoe UI", 7))
            return
        lo  = 0
        hi  = max(vals) or 1
        pad = 4
        gw  = w - pad * 2
        gh  = h - pad * 2 - 10
        n   = len(vals)
        xs  = [pad + int(i / max(n - 1, 1) * gw) for i in range(n)]
        ys  = [pad + gh - int((v - lo) / (hi - lo) * gh) for v in vals]
        # Grid
        cv.create_line(pad, pad + gh, w - pad, pad + gh,
                       fill=C["border"], width=1)
        # Labels
        cv.create_text(pad, pad, text=f"{hi:.0f}ms", anchor="nw",
                       fill=C["dim"], font=("Segoe UI", 6))
        cv.create_text(pad, h - 2, text="0ms", anchor="sw",
                       fill=C["dim"], font=("Segoe UI", 6))
        # Timeout marks
        for i, tmo in enumerate(timeouts):
            if tmo:
                cv.create_line(xs[i], pad, xs[i], pad + gh,
                               fill=C["red"], width=1, dash=(2, 3))
        # RTT line (segment by segment to skip timeouts)
        avg = sum(v for v in vals if v) / max(sum(1 for v in vals if v), 1)
        for i in range(1, n):
            if timeouts[i] or timeouts[i - 1]:
                continue
            color = C["red"] if vals[i] > avg * 1.8 else C["green"]
            cv.create_line(xs[i-1], ys[i-1], xs[i], ys[i], fill=color, width=1)
        # Last dot
        if xs and not timeouts[-1]:
            last_color = C["red"] if vals[-1] > avg * 1.8 else C["green"]
            cv.create_oval(xs[-1]-2, ys[-1]-2, xs[-1]+2, ys[-1]+2,
                           fill=last_color, outline="")
        # Avg line
        avg_y = pad + gh - int((avg - lo) / (hi - lo) * gh) if hi > lo else pad + gh // 2
        cv.create_line(pad, avg_y, w - pad, avg_y,
                       fill=C["yellow"], width=1, dash=(4, 4))
        cv.create_text(w - pad - 2, avg_y - 2,
                       text=f"avg {avg:.0f}ms", anchor="se",
                       fill=C["yellow"], font=("Segoe UI", 6))

    def _build_map(self, parent):
        hf = tk.Frame(parent, bg=C["panel"])
        hf.pack(fill="x", padx=6, pady=(4, 2))
        tk.Label(hf, text="ROUTE MAP", bg=C["panel"], fg=C["accent"],
                 font=UI_B).pack(side="left")
        tk.Label(hf, text="  GeoIP hop positions",
                 bg=C["panel"], fg=C["dim"], font=("Segoe UI", 8)).pack(side="left")
        self._map_canvas = tk.Canvas(parent, bg="#080c12",
                                      highlightthickness=1,
                                      highlightbackground=C["border"])
        self._map_canvas.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        self._map_canvas.bind("<Configure>", lambda e: self._redraw_map())
        self._map_hops = {}   # hop_n -> (lat, lon)

    # ── Control ──────────────────────────────────────────────────────────────────

    def _toggle(self):
        if self._running:
            self._stop()
        else:
            self._start()

    def _start(self):
        target = self._target_var.get().strip()
        if not target:
            return
        self._running  = True
        self._start_ts = time.time()
        self._alerted  = set()
        self._map_hops.clear()
        self._btn.configure(text="■  Stop", bg="#6e1f1f", activebackground="#a12626")
        self._status_lbl.configure(text=f"  ● Running → {target}", fg=C["green"])
        self._clear()

        # Rename notebook tab to target
        nb     = self._app._notebook
        tab_id = nb.select()
        nb.tab(tab_id, text=f"  {target[:22]}  ")

        def on_new_ip(ip):
            self._geo.fetch_if_needed(ip)
            try:
                self.frame.after(50, self._refresh_map_for_ip, ip)
            except Exception:
                pass

        self._mtr    = MTR(target, lambda s: self.frame.after(0, self._on_mtr,  s),
                           on_new_ip=on_new_ip, force_ipv6=self._ipv6)
        self._pinger = Pinger(target, lambda s: self.frame.after(0, self._on_ping, s))
        self._lookup = Lookup(target, lambda r: self.frame.after(0, self._on_info, r),
                              force_ipv6=self._ipv6, features=dict(self._features))

        def _target_geo():
            try:
                self._geo.fetch_if_needed(socket.gethostbyname(target))
            except Exception:
                pass
        threading.Thread(target=_target_geo, daemon=True).start()

        self._mtr.start()
        self._pinger.start()
        self._lookup.start()

    def _stop(self):
        if not self._running:
            return
        self._running = False
        duration = time.time() - self._start_ts if self._start_ts else 0
        if self._mtr:    self._mtr.stop()
        if self._pinger: self._pinger.stop()
        self._btn.configure(text="▶  Start", bg="#238636", activebackground="#2ea043")
        self._status_lbl.configure(text="  Stopped", fg=C["dim"])

        if self._mtr and self._mtr.hops:
            snap      = self._mtr.snapshot()
            target    = self._target_var.get().strip()
            hops_data = [{"n": n, "ip": h.ip, "host": h.host, "loss": h.loss,
                           "avg": h.avg, "best": h.best, "worst": h.worst, "sent": h.sent}
                          for n, h in sorted(snap.items())]
            threading.Thread(target=_db_save_run,
                             args=(target, duration, hops_data), daemon=True).start()

    def stop(self):
        if self._mtr:    self._mtr.stop()
        if self._pinger: self._pinger.stop()

    def _close(self):
        self._app._close_tab(self)

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
        self._rtt_history.clear()
        self._redraw_rtt_graph()

    # ── Callbacks ────────────────────────────────────────────────────────────────

    def _on_mtr(self, snap):
        existing = {int(self._tree.set(item, "hop")): item
                    for item in self._tree.get_children()}
        alerted_now = False
        for n in sorted(snap.keys()):
            h    = snap[n]
            disp = h.host if h.host else (h.ip or "???")
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

            if h.ip and n not in self._alerted:
                avg = h.avg
                if (loss >= self._thresh_loss or
                        (avg is not None and avg >= self._thresh_ms)):
                    self._alerted.add(n)
                    alerted_now = True
                    ts     = datetime.now().strftime("%H:%M:%S")
                    reason = (f"loss={loss:.1f}%" if loss >= self._thresh_loss
                              else f"avg={avg:.0f}ms")
                    disp_h = h.host if h.host else h.ip
                    self._log_alert(f"[{ts}] Hop {n}  {disp_h}  {reason}")

            row  = (str(n), h.spark, disp, h.ip or "* * *",
                    f"{loss:.1f}%", str(h.sent), str(h.recv),
                    h.ms(h.last), h.ms(h.avg), h.ms(h.best),
                    h.ms(h.worst), h.ms(h.stdev))
            tags = (tag, "altbg") if n % 2 == 0 else (tag,)

            if n in existing:
                for col, val in zip(
                    ["hop","spark","host","ip","loss","snt","rcv",
                     "last","avg","best","wrst","stdev"], row):
                    self._tree.set(existing[n], col, val)
                self._tree.item(existing[n], tags=tags)
            else:
                self._tree.insert("", "end", values=row, tags=tags)

        if alerted_now and self._app.sounds_enabled:
            self._app.bell()

    def _on_ping(self, stats):
        def ms(v): return f"{v:.1f}ms" if v is not None else "—"
        self._ping_vars["Sent"].set(str(stats["sent"]))
        self._ping_vars["Recv"].set(str(stats["recv"]))
        self._ping_vars["Loss%"].set(f"{stats['loss']:.1f}%")
        self._ping_vars["Last"].set(ms(stats["last"]))
        self._ping_vars["Avg"].set(ms(stats["avg"]))
        self._ping_vars["Best"].set(ms(stats["best"]))
        self._ping_vars["Worst"].set(ms(stats["worst"]))
        self._ping_vars["StDev"].set(ms(stats["stdev"]))
        entry = stats.get("latest")
        if entry:
            ts, rtt, ip = entry
            self._rtt_history.append(rtt)
            self._redraw_rtt_graph()
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
        if key not in self._info_texts or key == "alerts":
            return
        t = self._info_texts[key]
        t.configure(state="normal")
        t.delete("1.0", "end")
        t.insert("1.0", data)
        lines = data.count("\n") + 1
        t.configure(height=max(3, min(lines + 1, 30)), state="disabled")

    def _log_alert(self, msg):
        if "alerts" not in self._info_texts:
            return
        t = self._info_texts["alerts"]
        t.configure(state="normal")
        existing = t.get("1.0", "end").strip()
        t.insert("end", ("\n" if existing else "") + msg)
        lines = int(t.index("end-1c").split(".")[0])
        t.configure(height=max(3, min(lines + 1, 10)), state="disabled")

    # ── Route map ────────────────────────────────────────────────────────────────

    def _refresh_map_for_ip(self, ip):
        if not self._mtr:
            return
        snap = self._mtr.snapshot()
        for n, hop in snap.items():
            if hop.ip == ip:
                geo = self._geo.get(ip)
                if geo:
                    self._map_hops[n] = (geo["lat"], geo["lon"])
        self._redraw_map()

    def _redraw_map(self):
        cv = self._map_canvas
        w  = cv.winfo_width()
        h  = cv.winfo_height()
        if w < 10 or h < 10:
            return
        cv.delete("all")
        cv.create_rectangle(0, 0, w, h, fill="#080c12", outline="")

        # Graticule
        for lat in range(-90, 91, 30):
            y     = int((90 - lat) / 180 * h)
            color = "#183050" if lat == 0 else "#0f1a24"
            cv.create_line(0, y, w, y, fill=color, width=2 if lat == 0 else 1)
        for lon in range(-180, 181, 30):
            x     = int((lon + 180) / 360 * w)
            color = "#183050" if lon == 0 else "#0f1a24"
            cv.create_line(x, 0, x, h, fill=color, width=2 if lon == 0 else 1)

        # Labels
        for lat, lbl in [(-60, "60S"), (-30, "30S"), (0, "EQ"), (30, "30N"), (60, "60N")]:
            cv.create_text(3, int((90 - lat) / 180 * h),
                           text=lbl, anchor="w", fill="#1e3a52", font=("Segoe UI", 6))

        if not self._map_hops:
            msg = ("install requests for route map" if not HAS_REQ
                   else "waiting for hop geo data…")
            cv.create_text(w // 2, h // 2, text=msg, fill=C["dim"],
                           font=("Segoe UI", 8))
            return

        sorted_hops = sorted(self._map_hops.items())

        def _xy(lat, lon):
            return int((lon + 180) / 360 * w), int((90 - lat) / 180 * h)

        # Path lines
        pts = [_xy(lat, lon) for _, (lat, lon) in sorted_hops]
        for i in range(len(pts) - 1):
            cv.create_line(pts[i][0], pts[i][1], pts[i+1][0], pts[i+1][1],
                           fill="#1a4a7a", width=1, dash=(4, 3))

        # Hop markers
        max_n = sorted_hops[-1][0] if sorted_hops else 0
        for n, (lat, lon) in sorted_hops:
            x, y   = _xy(lat, lon)
            is_dst = (n == max_n)
            color  = C["accent"] if is_dst else C["green"]
            r      = 5 if is_dst else 4
            cv.create_oval(x - r, y - r, x + r, y + r,
                           fill=color, outline="white", width=1)
            cv.create_text(x + 7, y, text=str(n), anchor="w",
                           fill=C["fg"], font=("Segoe UI", 7))

    # ── Tooltip ──────────────────────────────────────────────────────────────────

    def _on_tree_motion(self, event):
        item = self._tree.identify_row(event.y)
        if not item:
            self._hide_tooltip()
            return
        if item == self._last_tooltip_item:
            if self._tooltip_win:
                rx = self._tree.winfo_rootx() + event.x + 18
                ry = self._tree.winfo_rooty() + event.y + 12
                self._tooltip_win.geometry(f"+{rx}+{ry}")
            return
        self._last_tooltip_item = item
        self._show_tooltip(event, item)

    def _show_tooltip(self, event, item):
        self._hide_tooltip()
        ip   = self._tree.set(item, "ip")
        hop  = self._tree.set(item, "hop")
        host = self._tree.set(item, "host")
        if not ip or ip == "* * *":
            return
        geo = self._geo.get(ip)
        win = tk.Toplevel(self._tree)
        win.wm_overrideredirect(True)
        win.configure(bg=C["border"])
        win.attributes("-topmost", True)
        inner = tk.Frame(win, bg=C["widget"], padx=10, pady=8)
        inner.pack(padx=1, pady=1)
        lines = [(f"Hop {hop}", C["accent"], ("Segoe UI", 9, "bold")),
                 (ip, C["fg"], MONO_SM)]
        if host and host != ip:
            lines.append((host, C["dim"], MONO_SM))
        if geo:
            city    = geo.get("city", "")
            country = geo.get("country", "")
            cc      = geo.get("cc", "")
            if country:
                lines.append((f"{city}, {country} ({cc})" if city else country,
                               C["fg"], UI))
            if geo.get("asn"):
                lines.append((geo["asn"], C["dim"], MONO_SM))
            if geo.get("isp"):
                lines.append((geo["isp"], C["dim"], MONO_SM))
            lines.append((f"{geo['lat']:.2f}°, {geo['lon']:.2f}°", C["dim"], MONO_SM))
        else:
            lines.append(("fetching geo data…", C["dim"], UI))
        for text, fg, font in lines:
            tk.Label(inner, text=text, bg=C["widget"], fg=fg,
                     font=font, anchor="w").pack(anchor="w")
        rx = self._tree.winfo_rootx() + event.x + 18
        ry = self._tree.winfo_rooty() + event.y + 12
        win.geometry(f"+{rx}+{ry}")
        self._tooltip_win = win

    def _hide_tooltip(self):
        if self._tooltip_win:
            try:
                self._tooltip_win.destroy()
            except Exception:
                pass
            self._tooltip_win = None
        self._last_tooltip_item = None

    # ── Right-click context menu ──────────────────────────────────────────────────

    def _on_tree_right_click(self, event):
        item = self._tree.identify_row(event.y)
        if not item:
            return
        self._tree.selection_set(item)
        ip   = self._tree.set(item, "ip")
        host = self._tree.set(item, "host")
        menu = tk.Menu(self._tree, tearoff=0,
                       bg=C["widget"], fg=C["fg"],
                       activebackground=C["accent"], activeforeground="white",
                       relief="flat", bd=0)
        menu.add_command(label=f"Copy IP     {ip}",
                         command=lambda: self._clip(ip))
        menu.add_command(label=f"Copy Hostname  {host or ip}",
                         command=lambda: self._clip(host or ip))
        geo = self._geo.get(ip) if (ip and ip != "* * *") else None
        if geo and geo.get("country"):
            menu.add_separator()
            menu.add_command(
                label=f"  {geo.get('city','')} · {geo['country']} · {geo.get('asn','')}",
                state="disabled")
        menu.tk_popup(event.x_root, event.y_root)

    def _clip(self, text):
        self._app.clipboard_clear()
        self._app.clipboard_append(text)

    # ── Export ───────────────────────────────────────────────────────────────────

    def _export(self):
        target = self._target_var.get().strip() or "cooltr"
        ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe   = re.sub(r"[^\w\-.]", "_", target)
        path   = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[
                ("Text file", "*.txt"),
                ("JSON file", "*.json"),
                ("CSV file",  "*.csv"),
                ("All files", "*.*"),
            ],
            initialfile=f"cooltr_{safe}_{ts}.txt",
            title="Export CoolTR Results")
        if not path:
            return
        ext = os.path.splitext(path)[1].lower()
        try:
            if ext == ".json":
                self._export_json(path, target)
            elif ext == ".csv":
                self._export_csv(path, target)
            else:
                self._export_txt(path, target)
        except Exception as e:
            messagebox.showerror("Export Failed", str(e), parent=self._app)

    def _hop_rows(self):
        cols = ["hop", "host", "ip", "loss", "snt", "rcv",
                "last", "avg", "best", "wrst", "stdev"]
        return [{c: self._tree.set(item, c) for c in cols}
                for item in self._tree.get_children()]

    def _export_txt(self, path, target):
        lines = [
            f"CoolTR Export  —  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Target : {target}", "=" * 70, "", "TRACEROUTE", "-" * 70,
        ]
        for v in self._hop_rows():
            lines.append(
                f"  {v['hop']:>3}  {v['ip']:<16}  {v['host'][:28]:<28}  "
                f"loss={v['loss']:<7} avg={v['avg']:<8} "
                f"best={v['best']:<8} worst={v['wrst']:<8} snt={v['snt']}")
        lines += ["", "NETWORK INFO", "-" * 70]
        for key, t in self._info_texts.items():
            data = t.get("1.0", "end").strip()
            if data:
                lines += [f"\n[{key.upper()}]", data]
        lines += ["", "PING STATS", "-" * 70]
        for label, var in self._ping_vars.items():
            lines.append(f"  {label}: {var.get()}")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))

    def _export_json(self, path, target):
        info = {k: t.get("1.0", "end").strip()
                for k, t in self._info_texts.items()}
        data = {
            "exported":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target":    target,
            "traceroute": self._hop_rows(),
            "ping_stats": {l: v.get() for l, v in self._ping_vars.items()},
            "info":      info,
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)

    def _export_csv(self, path, target):
        rows = self._hop_rows()
        with open(path, "w", newline="", encoding="utf-8") as fh:
            if rows:
                writer = csv.DictWriter(fh, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)

    # ── Threshold popup ───────────────────────────────────────────────────────────

    def _open_thresholds(self):
        ThresholdConfig(self._app, self)

    def _toggle_ipv6(self):
        self._ipv6 = not self._ipv6
        if self._ipv6:
            self._ipv6_btn.configure(text="IPv6", fg=C["accent"])
        else:
            self._ipv6_btn.configure(text="IPv4", fg=C["dim"])

    def _refresh_target_history(self):
        self._target["values"] = _db_get_targets()

    # ── Helpers ──────────────────────────────────────────────────────────────────

    def _copy_text(self, widget):
        text = widget.get("1.0", "end").strip()
        self._app.clipboard_clear()
        self._app.clipboard_append(text)


# ─── Main Application ────────────────────────────────────────────────────────────
class CoolTR(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CoolTR — Cool TraceRoute")
        self.geometry("1480x900")
        self.minsize(1100, 700)
        self.configure(bg=C["bg"])
        self._geo_cache     = GeoCache()
        self._sessions      = []
        self.sounds_enabled = False
        _db_init()
        self._build()
        self._apply_style()

    def _build(self):
        self._build_main_header()
        self._notebook = ttk.Notebook(self)
        self._notebook.pack(fill="both", expand=True, padx=4, pady=(0, 4))
        self._add_session()

    def _build_main_header(self):
        hdr = tk.Frame(self, bg=C["panel"], height=48)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        _icon_path = os.path.join(_APP_DIR, "cooltr_icon.png")
        if os.path.exists(_icon_path):
            try:
                self._header_icon = tk.PhotoImage(file=_icon_path).subsample(8, 8)
                tk.Label(hdr, image=self._header_icon, bg=C["panel"]).pack(
                    side="left", padx=(10, 0), pady=6)
            except Exception:
                self._header_icon = None

        tk.Label(hdr, text="CoolTR", bg=C["panel"], fg=C["accent"],
                 font=("Segoe UI", 13, "bold")).pack(side="left", padx=(6, 4), pady=8)
        tk.Label(hdr, text="·  Cool TraceRoute", bg=C["panel"], fg=C["dim"],
                 font=("Segoe UI", 10)).pack(side="left", pady=8)

        tk.Frame(hdr, bg=C["border"], width=1).pack(side="left", fill="y", padx=12, pady=8)

        tk.Button(hdr, text="＋  New Tab", bg=C["widget"], fg=C["dim"],
                  activebackground=C["border"], activeforeground=C["fg"],
                  relief="flat", font=("Segoe UI", 8), padx=10,
                  cursor="hand2", command=self._add_session).pack(
            side="left", ipady=2)

        tk.Button(hdr, text="⏱  History", bg=C["widget"], fg=C["dim"],
                  activebackground=C["border"], activeforeground=C["fg"],
                  relief="flat", font=("Segoe UI", 8), padx=10,
                  cursor="hand2", command=self._show_history).pack(
            side="left", padx=6, ipady=2)

        self._sounds_btn = tk.Button(
            hdr, text="🔇  Sounds Off", bg=C["widget"], fg=C["dim"],
            activebackground=C["border"], activeforeground=C["fg"],
            relief="flat", font=("Segoe UI", 8), padx=10,
            cursor="hand2", command=self._toggle_sounds)
        self._sounds_btn.pack(side="left", ipady=2)

        deps = []
        if HAS_REQ:   deps.append("requests ✓")
        else:         deps.append("requests ✗  (pip install requests)")
        if HAS_DNS:   deps.append("dnspython ✓")
        if HAS_WHOIS: deps.append("python-whois ✓")
        tk.Label(hdr, text="  |  ".join(deps), bg=C["panel"], fg=C["dim"],
                 font=("Segoe UI", 7)).pack(side="right", padx=10)

    def _toggle_sounds(self):
        self.sounds_enabled = not self.sounds_enabled
        if self.sounds_enabled:
            self._sounds_btn.configure(text="🔔  Sounds On",  fg=C["accent"])
        else:
            self._sounds_btn.configure(text="🔇  Sounds Off", fg=C["dim"])

    def _add_session(self):
        sess = SessionTab(self._notebook, self, self._geo_cache)
        self._sessions.append(sess)
        self._notebook.add(sess.frame, text=f"  Tab {len(self._sessions)}  ")
        self._notebook.select(sess.frame)
        sess._target.focus_set()

    def _close_tab(self, session):
        session.stop()
        if session in self._sessions:
            self._sessions.remove(session)
        self._notebook.forget(session.frame)
        if not self._sessions:
            self._add_session()

    def _show_history(self):
        HistoryViewer(self)

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
        s.configure("TNotebook",
            background=C["bg"], borderwidth=0)
        s.configure("TNotebook.Tab",
            background=C["panel"], foreground=C["dim"],
            padding=[8, 4], font=("Segoe UI", 9))
        s.map("TNotebook.Tab",
            background=[("selected", C["widget"])],
            foreground=[("selected", C["fg"])])
        s.configure("TCombobox",
            background=C["widget"], foreground=C["fg"],
            fieldbackground=C["widget"], insertcolor=C["fg"],
            selectbackground=C["accent"], selectforeground="white",
            arrowcolor=C["dim"])
        s.map("TCombobox",
            fieldbackground=[("readonly", C["widget"]), ("!readonly", C["widget"])],
            foreground=[("readonly", C["fg"]), ("!readonly", C["fg"])])
        self.option_add("*TCombobox*Listbox.background",        C["widget"])
        self.option_add("*TCombobox*Listbox.foreground",        C["fg"])
        self.option_add("*TCombobox*Listbox.selectBackground",  C["accent"])
        self.option_add("*TCombobox*Listbox.selectForeground",  "white")
        self.option_add("*TCombobox*Listbox.font",              ("Consolas", 10))

    def on_close(self):
        for sess in self._sessions:
            sess.stop()
        self.destroy()


# ─── Entry point ─────────────────────────────────────────────────────────────────
def main():
    app = CoolTR()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()


if __name__ == "__main__":
    main()
