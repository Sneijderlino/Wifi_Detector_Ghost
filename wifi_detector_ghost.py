#Final 

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WiFi Intrusion Detector (Final)
- Bahasa Indonesia
- Tambahan: banner, clear screen, efek menyeramkan, progress bar, port+dir scan (opsional)
- Perubahan minimal pada logic asli deteksi
"""

import os
import sys
import time
import socket
import ssl
import logging
import signal
import threading
from collections import defaultdict, deque
from urllib.parse import urljoin
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# scapy & colorama
from scapy.all import sniff, Dot11, ARP, Dot11Deauth, Dot11Elt, AsyncSniffer
from colorama import Fore, Style, init

# pyfiglet optional
try:
    import pyfiglet
    _HAS_PYFIGLET = True
except Exception:
    _HAS_PYFIGLET = False

# init warna terminal
init(autoreset=True)

# logging
logging.basicConfig(
    filename="wifi_guard.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# -----------------------------
# Konfigurasi threshold (tetap dari kode asli)
DEAUTH_THRESHOLD = 5
DEAUTH_WINDOW = 10
PROBE_THRESHOLD = 30
PROBE_WINDOW = 5
NEW_CLIENT_THRESHOLD = 10
NEW_CLIENT_WINDOW = 60

# ADDED state untuk deauth start/stop (minimal)
deauth_counts = defaultdict(lambda: deque())
deauth_state = {}
from threading import Lock
lock = Lock()
NO_DEAUTH_TIMEOUT = 20
CLEANER_INTERVAL = 1.0

probe_counts = defaultdict(lambda: deque())
new_clients = defaultdict(list)
arp_table = {}
ap_info = defaultdict(dict)

running = True
sniffer = None

# WPS cooldown & whitelist
WPS_ALERT_COOLDOWN = 60.0
wps_last_alert = {}
WHITELIST_BSSID = set([
    # Tambahkan BSSID routermu yang ingin diabaikan, contoh:
    # "f4:f6:47:a6:05:e4",
])

# -----------------------------
# Warna untuk status (sesuai permintaan)
COLOR_SAFE = Fore.GREEN
COLOR_DANGER = Fore.RED
COLOR_WARN = Fore.YELLOW
COLOR_INFO = Fore.CYAN
COLOR_INFO2 = Fore.MAGENTA

# Helper printing hasil list style
def print_result_ok(msg, warna=COLOR_SAFE):
    print(f"{warna}[✓]{Style.RESET_ALL} {msg}")

def print_result_warn(msg, warna=COLOR_WARN):
    print(f"{warna}[!]{Style.RESET_ALL} {msg}")

# Fungsi terminal alert (menggantikan previous terminal_alert)
def terminal_alert(jenis, pesan, level="WARN"):
    """
    Menampilkan notifikasi hasil deteksi (satu baris), Bahasa Indonesia.
    Format tetap ringkas dan berwarna.
    """
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    tag = f"{ts} TERDETEKSI: {jenis} — {pesan}"
    # Pilih warna berdasarkan jenis
    if jenis in ("DEAUTH", "DEAUTH_BERHENTI", "ARP_SPOOF"):
        # bahaya
        print(f"{COLOR_DANGER}{Style.BRIGHT}{tag}{Style.RESET_ALL}")
        logging.warning(f"{jenis} — {pesan}")
    elif jenis in ("ROGUE_AP", "EVIL_TWIN"):
        print(f"{COLOR_INFO2}{Style.BRIGHT}{tag}{Style.RESET_ALL}")
        logging.warning(f"{jenis} — {pesan}")
    elif jenis in ("WPS", "JARINGAN_TERBUKA"):
        print(f"{COLOR_WARN}{Style.BRIGHT}{tag}{Style.RESET_ALL}")
        logging.warning(f"{jenis} — {pesan}")
    else:
        print(f"{COLOR_INFO}{Style.BRIGHT}{tag}{Style.RESET_ALL}")
        logging.info(f"{jenis} — {pesan}")

# -----------------------------
# Cleaner thread untuk deauth STOP
def cleaner_loop():
    global running
    while running:
        now = time.time()
        with lock:
            for mac, dq in list(deauth_counts.items()):
                while dq and now - dq[0] > DEAUTH_WINDOW:
                    dq.popleft()
                st = deauth_state.get(mac)
                if st:
                    if st.get("active") and (now - st.get("last_seen", 0) > NO_DEAUTH_TIMEOUT):
                        st["active"] = False
                        terminal_alert("DEAUTH_BERHENTI", f"MAC sumber {mac} tidak mengirim deauth selama {NO_DEAUTH_TIMEOUT}s (serangan dianggap berhenti)", level="INFO")
                        logging.info(f"Deauth stopped for {mac}")
            # cleanup probe
            for mac, dq in list(probe_counts.items()):
                while dq and now - dq[0] > PROBE_WINDOW:
                    dq.popleft()
            # cleanup new clients
            for ap, lst in list(new_clients.items()):
                new_clients[ap] = [(c, t) for c, t in lst if now - t <= NEW_CLIENT_WINDOW]
        time.sleep(CLEANER_INTERVAL)

# -----------------------------
# Handler deauth (minimal changes)
def handle_deauth(pkt, now):
    src = getattr(pkt, "addr2", None)
    tgt = getattr(pkt, "addr1", None)
    if not src:
        return
    with lock:
        deauth_counts[src].append(now)
        while deauth_counts[src] and now - deauth_counts[src][0] > DEAUTH_WINDOW:
            deauth_counts[src].popleft()
        st = deauth_state.setdefault(src, {"active": False, "last_seen": now})
        st["last_seen"] = now
        if len(deauth_counts[src]) >= DEAUTH_THRESHOLD:
            if not st["active"]:
                st["active"] = True
                pesan = f"MAC sumber {src} mengirim {len(deauth_counts[src])} paket deauth dalam {DEAUTH_WINDOW}s target={tgt}"
                terminal_alert("DEAUTH", pesan)
                logging.info(f"DEAUTH_START {src} count={len(deauth_counts[src])} target={tgt}")
            else:
                logging.debug(f"DEAUTH berlanjut dari {src} count={len(deauth_counts[src])}")

# -----------------------------
# Detektor utama (tetap logika asli, hanya pesan Bahasa Indonesia)
def detect(pkt):
    now = time.time()
    try:
        # Deauth
        if pkt.haslayer(Dot11Deauth):
            handle_deauth(pkt, now)
            return

        # Beacon / ProbeResp -> info AP, rogue, WPS, open
        if pkt.haslayer(Dot11Elt) and getattr(pkt, "type", None) == 0 and getattr(pkt, "subtype", None) in (8, 5):
            ssid = pkt.info.decode(errors="ignore") if isinstance(pkt.info, (bytes, bytearray)) else str(pkt.info)
            bssid = getattr(pkt, "addr2", None)

            if ssid and bssid:
                if "ssid" not in ap_info[bssid]:
                    ap_info[bssid]["ssid"] = ssid

            if ssid:
                ssids = [info.get("ssid") for info in ap_info.values()]
                if ssids.count(ssid) > 1:
                    bssids = [k for k, v in ap_info.items() if v.get("ssid") == ssid]
                    terminal_alert("ROGUE_AP", f"SSID '{ssid}' muncul di beberapa BSSID: {bssids}")

            # WPS detection: rate-limit + whitelist
            elt = pkt.getlayer(Dot11Elt)
            while elt:
                try:
                    if elt.ID == 221 and b"\x00\x50\xf2\x04" in elt.info:
                        if bssid and (bssid.lower() in {x.lower() for x in WHITELIST_BSSID}):
                            pass
                        else:
                            last = wps_last_alert.get(bssid, 0)
                            if now - last >= WPS_ALERT_COOLDOWN:
                                wps_last_alert[bssid] = now
                                terminal_alert("WPS", f"AP {bssid} (SSID:{ssid}) mengiklankan WPS")
                            else:
                                logging.debug(f"WPS alert skipped for {bssid} (cooldown)")
                except Exception:
                    pass
                elt = elt.payload.getlayer(Dot11Elt)

            # Open network detection
            try:
                cap = pkt.sprintf("{Dot11.cap%04xr}").lower()
                if "privacy" not in cap:
                    if bssid and (bssid.lower() in {x.lower() for x in WHITELIST_BSSID}):
                        pass
                    else:
                        terminal_alert("JARINGAN_TERBUKA", f"AP {bssid} (SSID:{ssid}) tidak menggunakan enkripsi")
            except Exception:
                pass
            return

        # Probe request -> probe flood
        if pkt.haslayer(Dot11) and getattr(pkt, "type", None) == 0 and getattr(pkt, "subtype", None) == 4:
            client = getattr(pkt, "addr2", None)
            if client:
                with lock:
                    probe_counts[client].append(now)
                    while probe_counts[client] and now - probe_counts[client][0] > PROBE_WINDOW:
                        probe_counts[client].popleft()
                    if len(probe_counts[client]) >= PROBE_THRESHOLD:
                        terminal_alert("PROBE_FLOOD", f"Klien {client} mengirim {len(probe_counts[client])} probe request dalam {PROBE_WINDOW}s")
            return

        # Data frame -> lonjakan klien baru
        if pkt.haslayer(Dot11) and getattr(pkt, "type", None) == 2:
            ap = getattr(pkt, "addr1", None)
            client = getattr(pkt, "addr2", None)
            if ap and client:
                if client not in [c for c, _ in new_clients[ap]]:
                    new_clients[ap].append((client, now))
                new_clients[ap] = [(c, t) for c, t in new_clients[ap] if now - t <= NEW_CLIENT_WINDOW]
                cnt = len(new_clients[ap])
                if cnt >= NEW_CLIENT_THRESHOLD:
                    ssid = ap_info.get(ap, {}).get("ssid", "?")
                    terminal_alert("LONJAKAN_KLIEN", f"AP {ap} (SSID:{ssid}) menerima {cnt} klien baru dalam {NEW_CLIENT_WINDOW}s")
            return

        # ARP spoof
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            if ip in arp_table and arp_table[ip] != mac:
                terminal_alert("ARP_SPOOF", f"IP {ip} sebelumnya MAC {arp_table[ip]}, sekarang terlihat dari {mac}")
            arp_table[ip] = mac
            return

    except Exception as e:
        logging.exception(f"Error di detect(): {e}")

# -----------------------------
# Shutdown handler
def shutdown(signum, frame):
    global running, sniffer
    print("\n[!] Ctrl+C diterima — menghentikan sniffer...")
    running = False
    try:
        if sniffer:
            sniffer.stop()
    except Exception:
        pass

# -----------------------------
# Utility: banner, animasi, progress bar, scans
def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def show_banner():
    banner_text = "Wifi_detector"
    if _HAS_PYFIGLET:
        # coba font "abstract" dulu, fallback "slant"
        try:
            banner = pyfiglet.figlet_format(banner_text, font="abstract")
        except Exception:
            try:
                banner = pyfiglet.figlet_format(banner_text, font="slant")
            except Exception:
                banner = banner_text
    else:
        # tanpa pyfiglet gunakan teks sederhana artful
        banner = (
            " _       _ _      _   _           _             _             \n"
            "| |     (_) |    | | | |         | |           | |            \n"
            "| | ___  _| |_ __| |_| |__   ___ | | ___   __ _| | ___  _ __  \n"
            "| |/ _ \\| | __/ _` | | '_ \\ / _ \\| |/ _ \\ / _` | |/ _ \\| '_ \\ \n"
            "| | (_) | | || (_| | | |_) | (_) | | (_) | (_| | | (_) | | | |\n"
            "|_|\\___/|_|\\__\\__,_|_|_.__/ \\___/|_|\\___/ \\__, |_|\\___/|_| |_|\n"
            "                                           __/ |             \n"
            "                                          |___/              \n"
        )
    # print banner berwarna merah
    print(COLOR_DANGER + banner + Style.RESET_ALL)
    print(COLOR_DANGER + Style.BRIGHT + "Tools by ghost_root\n" + Style.RESET_ALL)

def creepy_init():
    msg = "Initializing attack module"
    for i in range(3):
        sys.stdout.write("\r" + COLOR_INFO2 + msg + "." * (i + 1) + " " * (3 - i))
        sys.stdout.flush()
        time.sleep(0.5)
    print("\n")

def progress_bar(duration=2.0):
    total_steps = 40
    step_sleep = duration / total_steps
    for i in range(total_steps + 1):
        pct = int((i / total_steps) * 100)
        filled = int((i / total_steps) * 20)
        bar = "=" * filled + " " * (20 - filled)
        sys.stdout.write(f"\r{COLOR_INFO}SCANNING... [{bar}] {pct}%{Style.RESET_ALL}")
        sys.stdout.flush()
        time.sleep(step_sleep)
    print("\n")

# -----------------------------
# Simple port scanner & directory scanner (opsional)
def port_scan(host, ports, timeout=0.5):
    results = {}
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            res = s.connect_ex((host, p))
            if res == 0:
                results[p] = True
            else:
                results[p] = False
        except Exception:
            results[p] = False
        finally:
            try:
                s.close()
            except Exception:
                pass
    return results

def dir_scan(base_host, paths, timeout=2.0):
    """
    base_host can be domain or ip, with or without http(s).
    We'll try http and https.
    Returns dict path -> (found: bool, code:int or err)
    """
    results = {}
    # normalize
    schemes = ["http://", "https://"]
    for p in paths:
        found = False
        info = None
        for scheme in schemes:
            url = scheme + base_host if base_host.startswith(("http://","https://")) == False else base_host
            # ensure single slash join
            full = url.rstrip("/") + "/" + p.lstrip("/")
            try:
                req = Request(full, headers={"User-Agent": "Mozilla/5.0"})
                with urlopen(req, timeout=timeout) as resp:
                    code = resp.getcode()
                    if 200 <= code < 400:
                        found = True
                        info = code
                        break
                    else:
                        info = code
            except HTTPError as e:
                info = getattr(e, "code", str(e))
                # 401/403 still means resource exists but protected; treat as found
                if hasattr(e, "code") and e.code in (401, 403):
                    found = True
                    break
            except URLError as e:
                info = str(e.reason)
            except Exception as e:
                info = str(e)
        results[p] = (found, info)
    return results

# -----------------------------
# MAIN
if __name__ == "__main__":
    # Clear screen and show banner + effects
    clear_screen()
    show_banner()
    creepy_init()
    progress_bar(duration=1.5)

    # Opsional: tanya user apakah ingin menjalankan port & dir scan
    try:
        do_scan = input("Jalankan port & directory scan dulu? (y/n) [n]: ").strip().lower() or "n"
    except Exception:
        do_scan = "n"

    if do_scan == "y":
        target = input("Masukkan target (IP atau domain tanpa schema, contoh: 192.168.1.1 atau example.com): ").strip()
        # default ports & paths
        ports = [21, 22, 80, 443, 8080]
        paths = ["/login", "/admin", "/robots.txt", "/dashboard"]
        print("\n" + COLOR_INFO + "Mulai port scan..." + Style.RESET_ALL)
        port_results = port_scan(target, ports)
        for p, open_ in port_results.items():
            if open_:
                print_result_ok(f"Port {p} terbuka pada {target}", warna=COLOR_DANGER)  # open ports can be 'interesting' -> merah
            else:
                print_result_warn(f"Port {p} tertutup pada {target}", warna=COLOR_INFO)

        print("\n" + COLOR_INFO + "Mulai directory scan..." + Style.RESET_ALL)
        dir_results = dir_scan(target, paths)
        for path, (found, info) in dir_results.items():
            if found:
                print_result_ok(f"{path} ditemukan pada {target} (kode: {info})", warna=COLOR_DANGER)
            else:
                print_result_warn(f"{path} tidak ditemukan pada {target} (info: {info})", warna=COLOR_INFO)

        print("\n" + COLOR_INFO + "Scan selesai. Lanjut ke mode pemantauan WiFi." + Style.RESET_ALL)
        time.sleep(1.0)

    # Lanjut ke kode sniffing asli
    iface = input("Masukkan interface monitor (misal: wlan0mon): ").strip()
    print(COLOR_INFO + Style.BRIGHT + f"[+] Aktif — memantau interface {iface} (akan menampilkan HANYA serangan yang terdeteksi)" + Style.RESET_ALL)

    # start cleaner thread
    cleaner = threading.Thread(target=cleaner_loop, daemon=True)
    cleaner.start()

    # register Ctrl+C handler
    signal.signal(signal.SIGINT, shutdown)

    # start AsyncSniffer
    sniffer = AsyncSniffer(iface=iface, prn=detect, store=False)
    try:
        sniffer.start()
        while running:
            time.sleep(0.2)
    except Exception as e:
        logging.exception(f"Sniffer error: {e}")
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass
        print("[+] Sniffer dihentikan. Keluar.")