<p align="center">
  <img src="https://img.shields.io/badge/WiFi%20Tool-Intrusion%20Detector-red?style=for-the-badge&logo=python"/>
  <img src="https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge"/>
  <img src="https://img.shields.io/github/license/USERNAME/REPO?style=for-the-badge"/>
</p>

<h1 align="center">🚨 WiFi_Intrusion_Detector </h1>
<p align="center">
  All-in-one WiFi attack detection toolkit (Deauth → Rogue AP → ARP Spoof → Reporting).<br/>
  <em>Educational & Ethical Hacking Only — gunakan hanya pada jaringan yang Anda miliki izin eksplisit.</em>
</p>

---

<p align="center">
  <img src="/img/Banner.png" alt="Contoh output WiFi Intrusion Detector" width="800"/>
</p>

## 🔎 Ringkasan

_WiFi_Intrusion_Detector_ adalah toolkit Python untuk keamanan jaringan wireless:  
mendeteksi _deauthentication attack, rogue access point, probe flood, ARP spoofing, WPS exposure, dan open WiFi_.  
Script ini menampilkan output berwarna, efek animasi CLI, serta dapat melakukan port scanning & directory scanning opsional.

---

## ✨ Fitur Utama

- 🔴 _Deauth Attack Detector_ (pantau paket deauth real-time).
- 🟡 _Probe Flood Detector_.
- 🟣 _Rogue AP / Evil Twin Detector_.
- 🟡 _WPS Exposure Detector_.
- 🔵 _ARP Spoof Detector_.
- 🟢 _Open WiFi Detector_.
- 🎭 CLI interaktif dengan _banner, warna, animasi & progress bar_.
- 🌐 Opsional: _Port Scan & Directory Scan_.
- 📊 Log hasil scanning untuk analisis forensik.

---

## 📥 Cara Clone

```bash
git clone https://github.com/Sneijderlino/Wifi_Intrusion_Detector.git
cd Wifi_Intrusion_Detector
```

## Instalasi Kali Linux

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip git
pip3 install -r requirements.txt
#Rekomendasi Pakai Virtualenv
```

## Aktivkan Virtualenv

```bash
sudo apt update && sudo apt install -y python3-venv git
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## 📱 Instalasi di Termux (Android)

```bash
pkg update && pkg upgrade -y
pkg install -y python git
git clone https://github.com/Sneijderlino/Wifi_Intrusion_Detector.git
cd Wifi_Intrusion_Detector
pip install --upgrade pip
pip install -r requirements.txt
```

## 📱 Instalasi di Termux (Android)

```bash
pkg update && pkg upgrade -y
pkg install -y python git
git clone https://github.com/Sneijderlino/Wifi_Intrusion_Detector.git
cd Wifi_Intrusion_Detector
pip install --upgrade pip
pip install -r requirements.txt
```

## ⚠ Peringatan

```bash
#Catatan Wajib:
sebagian besar fitur deteksi (misalnya Deauth Attack)
butuh mode monitor WiFi → biasanya tidak didukung
Termux kecuali dengan root + external WiFi adapter.
Untuk fitur port scan / dir scan masih bisa digunakan.
```

## ▶ Cara Menjalankan

```bash
sudo python3 wifi_detector.py
Interface monitor dapat diaktifkan dengan:
sudo airmon-ng start wlan0
Script juga akan menanyakan apakah ingin menjalankan port & dir scan sebelum deteksi.
t
```

## 🖼 Demo / Contoh Output

<p align="center">
  <img src="/img/Awal.png" alt="Contoh output WiFi Intrusion Detector" width="800"/><br>
  <em>Demo Script Dijalankan: <code>sudo python3 wifi_detector.py</code></em>
</p>
<p align="center">
  <img src="/img/Serangan terdeteksi.png" alt="Contoh deteksi deauth attack" width="800"/><br>
  <em>Demo Deteksi Deauth Attack</em>
</p>

⚠ Disclaimer

<p>Script ini dibuat untuk pembelajaran & tujuan keamanan pribadi.
❌ Jangan digunakan untuk menyerang atau menguji jaringan orang lain tanpa izin eksplisit.</p>
# Wifi_Detector_Ghost
