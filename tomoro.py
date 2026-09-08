"""
Tomoro Coffee — Auto Daftar.

Mode:
  1) Interaktif (default jika dijalankan tanpa argumen)
       - Tanya OTP provider (manual / hero-sms)
       - Tanya jumlah akun
       - Tanya jumlah worker thread (default 3, hero-sms only)
       - Otomatis: validasi proxy → sewa nomor → ambil OTP → daftar
  2) Manual single  (--phone …)
       - Pakai nomor & OTP yang Anda input sendiri (mode lama)
  3) Bulk via flag  (--count N --workers W)
       - Sewa N nomor lewat OTP provider, daftar otomatis pakai W thread paralel

Alur per akun:
  1. precheck_proxy()  — pastikan proxy hidup & bisa reach Tomoro API
  2. acquire_phone()   — sewa nomor dari OTP provider (hemat saldo: hanya kalau proxy aman)
  3. send_sms / fetch_otp / verify / register / coupon list

Output:
  hasil.txt   TSV: phone<TAB>pin<TAB>expired<TAB>create_date
  hasil.json  detail lengkap per akun (akun, voucher, fingerprint device).
  logs/       audit raw response per akun.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import random
import secrets
import string
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any, Optional

import requests
from dotenv import load_dotenv

# Lokal
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from proxy_pool import ProxyPool, ProxyEntry, NoLiveProxyError, is_proxy_error
from otp_providers import make_provider, OTPProvider, Activation
from otp_providers.hero_sms import HeroSMSError
from sheets_sync import make_sheets_sync

load_dotenv(ROOT / ".env")


# ---------------------------------------------------------------------------
# Helper env
# ---------------------------------------------------------------------------

def env(key: str, default: str = "") -> str:
    v = os.getenv(key)
    return default if v is None or v == "" else v


def env_int(key: str, default: int) -> int:
    try:
        return int(env(key, str(default)))
    except ValueError:
        return default


def env_float(key: str, default: float) -> float:
    try:
        return float(env(key, str(default)))
    except ValueError:
        return default


def env_bool(key: str, default: bool) -> bool:
    return env(key, "1" if default else "0").strip().lower() in ("1", "true", "yes", "y", "on")


# --- Tomoro / persona settings ---
BASE_URL = env("BASE_URL", "https://api-service.tomoro-coffee.id").rstrip("/")
DEFAULT_PIN = env("DEFAULT_PIN", "000000")
DEFAULT_REF = env("DEFAULT_REF_CODE", "R568MT")
DEFAULT_AREA = env("DEFAULT_AREA_CODE", "62")

COUNTRY_CODE = env("COUNTRY_CODE", "id")
APP_LANGUAGE = env("APP_LANGUAGE", "en")
APP_CHANNEL = env("APP_CHANNEL", "google play")
REVISION = env("REVISION", "3.4.3")
USER_AGENT = env("USER_AGENT", "okhttp/5.1.0")
TIMEZONE = env("TIMEZONE", "Asia/Bangkok")
WTOKEN_PASSTHRU = env("WTOKEN_PASSTHRU", "")
SENDMSG_S_HEADER = env("SENDMSG_S_HEADER", "9464daa10b535370a24a2b978028e640")

# --- TigerTally wToken signer (frida bridge) ---
# Tomoro API sekarang di belakang Aliyun WAF: semua request MANDATORIAK header
# `wToken`, disign oleh native libtiger_tally.so (vmpSign(body_bytes)). Python
# saja tidak bisa kalkulasi itu → bridge ke rooted phone via frida-java-bridge
# daemon (see tigertally_bridge/). USE_SIGNER=1 = koppel wToken per request.
USE_SIGNER     = env_bool("USE_SIGNER", True)
SIGNER_URL     = env("SIGNER_URL", "http://127.0.0.1:8642")
SIGNER_TIMEOUT = env_int("SIGNER_TIMEOUT", 15)
SIGNER_RETRIES = env_int("SIGNER_RETRIES", 3)

MIN_AGE = env_int("MIN_AGE", 20)
MAX_AGE = env_int("MAX_AGE", 40)
BD_OFF_MIN = env_int("BIRTHDAY_OFFSET_MIN", 41)
BD_OFF_MAX = env_int("BIRTHDAY_OFFSET_MAX", 100)

JITTER_MIN = env_int("JITTER_MIN_MS", 800)
JITTER_MAX = env_int("JITTER_MAX_MS", 2500)

GEO_LON_MIN = env_float("GEO_LON_MIN", 95.0)
GEO_LON_MAX = env_float("GEO_LON_MAX", 141.0)
GEO_LAT_MIN = env_float("GEO_LAT_MIN", -10.5)
GEO_LAT_MAX = env_float("GEO_LAT_MAX", 5.5)

# --- OTP provider ---
OTP_PROVIDER_NAME = env("OTP_PROVIDER", "manual").strip().lower()
HERO_API_KEY     = env("HERO_SMS_API_KEY", "")
HERO_BASE_URL    = env("HERO_SMS_BASE_URL", "https://hero-sms.com/stubs/handler_api.php")
HERO_SERVICE     = env("HERO_SMS_SERVICE", "ang")
HERO_COUNTRY     = env("HERO_SMS_COUNTRY", "6")
HERO_OPERATOR    = env("HERO_SMS_OPERATOR", "any")
HERO_MAX_PRICE   = env_float("HERO_SMS_MAX_PRICE", 0.02)
HERO_OTP_TIMEOUT = env_int("HERO_SMS_OTP_TIMEOUT", 135)
HERO_POLL_SEC    = env_int("HERO_SMS_POLL_SEC", 5)

# --- Proxy ---
USE_PROXY      = env_bool("USE_PROXY", True)
PROXY_FILE     = env("PROXY_FILE", "proxy.txt")
PROXY_MAX_ATTEMPTS = env_int("PROXY_MAX_ATTEMPTS", 3)

# --- Bulk ---
DEFAULT_BULK_COUNT = env_int("DEFAULT_BULK_COUNT", 1)
MAX_BULK_COUNT     = env_int("MAX_BULK_COUNT", 50)
# Safety cap: berapa kali percobaan boleh dilakukan untuk mencapai N akun sukses.
# Misal target 5 akun & multiplier 3 → maksimal 15 percobaan. Mencegah saldo
# habis kalau OTP konsisten tidak masuk.
BULK_MAX_ATTEMPTS_MULT = env_int("BULK_MAX_ATTEMPTS_MULTIPLIER", 3)
BULK_DELAY_MIN     = env_int("BULK_INTER_ACCOUNT_DELAY_MIN", 3)
BULK_DELAY_MAX     = env_int("BULK_INTER_ACCOUNT_DELAY_MAX", 8)

# --- Threading ---
WORKER_THREADS     = env_int("WORKER_THREADS", 3)
MAX_WORKER_THREADS = env_int("MAX_WORKER_THREADS", 10)

# --- Google Sheets sync ---
SHEETS_ENABLED       = env_bool("SHEETS_ENABLED", True)
SHEETS_CREDS_FILE    = env("SHEETS_CREDS_FILE", "immm-484403-8d2ce46efaf2.json")
SHEETS_SPREADSHEET_ID = env("SHEETS_SPREADSHEET_ID", "1UsAXEfAxYeF3avIhxnme_OljERUhKP9-cs5V1MTRPUE")
SHEETS_WORKSHEET_GID  = env_int("SHEETS_WORKSHEET_GID", 1637012914)
SHEETS_WORKSHEET_NAME = env("SHEETS_WORKSHEET_NAME", "")

# --- Proxy precheck ---
# URL kecil untuk validasi proxy sebelum dipakai. Kalau gagal, proxy ditandai mati
# dan worker pindah ke proxy berikutnya — TANPA menghabiskan saldo OTP provider.
PROXY_PRECHECK_URL     = env("PROXY_PRECHECK_URL", "https://api-service.tomoro-coffee.id/portal/app/member/getPhoneArea")
PROXY_PRECHECK_TIMEOUT = env_int("PROXY_PRECHECK_TIMEOUT", 12)
# 0 = scan SELURUH pool sampai ketemu yang hidup (rekomendasi). >0 = batasi jumlah percobaan.
PROXY_PRECHECK_MAX_TRIES = env_int("PROXY_PRECHECK_MAX_TRIES", 0)


# ---------------------------------------------------------------------------
# Persona generator
# ---------------------------------------------------------------------------

FIRST_NAMES = [
    "Randi", "Adit", "Bima", "Citra", "Dimas", "Eka", "Fajar", "Galih",
    "Hari", "Indra", "Joko", "Kiki", "Lina", "Maya", "Nanda", "Okta",
    "Putra", "Qori", "Rizky", "Sari", "Tio", "Umar", "Vino", "Widya",
    "Yudha", "Zahra", "Anjas", "Bagas", "Cinta", "Devan", "Erika",
    "Faisal", "Gita", "Hendra", "Ika", "Jihan", "Kiana", "Luki", "Mira",
    "Niko", "Ovi", "Panji", "Risa", "Sandi", "Tiara", "Uli", "Vania",
    "Wira", "Yanti", "Zaki",
]
LAST_NAMES = [
    "alan", "ardi", "anto", "andra", "arta", "budi", "cahya", "dian",
    "dewi", "endra", "fitri", "gunawan", "hadi", "iswanto", "jaya",
    "kusuma", "lestari", "mahendra", "nirwana", "octavian", "permana",
    "rahayu", "santoso", "tama", "utama", "vidya", "wijaya", "yanto",
]
EMAIL_DOMAINS = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]


@dataclass
class Persona:
    nickname: str
    email: str
    gender: int
    birth: str
    device_code: str
    longitude: str
    latitude: str
    imei: str
    push_token: str
    advertising_id: str

    def to_log(self) -> dict[str, Any]:
        return asdict(self)


def gen_persona() -> Persona:
    first = random.choice(FIRST_NAMES)
    last = random.choice(LAST_NAMES).capitalize()
    nickname = f"{first} {last}"  # e.g. "Randi Alan" — Tomoro menyimpan apa adanya, lebih natural.
    # Email tidak boleh ada spasi → pakai versi tanpa spasi untuk local-part.
    email_local = f"{first}{last}"
    suffix_digits = "".join(random.choices(string.digits, k=random.randint(2, 4)))
    email = f"{email_local}{suffix_digits}@{random.choice(EMAIL_DOMAINS)}"

    today = date.today()
    age = random.randint(MIN_AGE, MAX_AGE)
    offset_days = random.randint(BD_OFF_MIN, BD_OFF_MAX)
    direction = random.choice([-1, 1])
    pivot = today + timedelta(days=direction * offset_days)
    try:
        birth_dt = pivot.replace(year=pivot.year - age)
    except ValueError:
        birth_dt = pivot.replace(month=2, day=28, year=pivot.year - age)

    return Persona(
        nickname=nickname,
        email=email,
        gender=random.choice([1, 2]),
        birth=birth_dt.isoformat(),
        device_code=secrets.token_hex(8),
        longitude=f"{random.uniform(GEO_LON_MIN, GEO_LON_MAX):.13f}",
        latitude=f"{random.uniform(GEO_LAT_MIN, GEO_LAT_MAX):.13f}",
        imei="".join(random.choices(string.digits, k=15)),
        push_token=secrets.token_hex(32),
        advertising_id=f"{secrets.token_hex(4)}-{secrets.token_hex(2)}-{secrets.token_hex(2)}-{secrets.token_hex(2)}-{secrets.token_hex(6)}",
    )


# ---------------------------------------------------------------------------
# Phone normalisation
# ---------------------------------------------------------------------------

def normalize_phone(raw: str) -> tuple[str, str]:
    """Terima 83xxx / 08xxx / 62xxx / +62xxx, dengan '-' '/' '.' '(' ')' spasi.

    Return (phone_lokal_tanpa_0, area_code).
    """
    if raw is None:
        raise ValueError("nomor kosong")
    s = "".join(c for c in raw if c.isdigit())
    if not s:
        raise ValueError("nomor kosong setelah normalisasi")
    area = DEFAULT_AREA
    if s.startswith("00"):
        s = s[2:]
    if s.startswith(area):
        s = s[len(area):]
    if s.startswith("0"):
        s = s[1:]
    if not s:
        raise ValueError("nomor kosong setelah normalisasi")
    return s, area


# ---------------------------------------------------------------------------
# HTTP client (Tomoro)
# ---------------------------------------------------------------------------

class TigerTallySigner:
    """Client ke frida-bridge daemon (tigertally_bridge/signer_daemon.py).

    Daemon lewat rooted phone memanggil TigerTallyAPI.vmpSign(type, bodyBytes)
    — kalkulasi wToken yang server Tomoro (Aliyun WAF) ceck.
    """

    def __init__(self, url: str = SIGNER_URL, timeout: int = SIGNER_TIMEOUT,
                 retries: int = SIGNER_RETRIES):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.retries = retries
        self._fail = False
        self._device_code: Optional[str] = None

    @property
    def available(self) -> bool:
        return USE_SIGNER and not self._fail and self.url != ""

    def bridge_device_code(self) -> str:
        """deviceCode ECHT dari app (via u0.m() hook).

        Server bind wToken aan device-hash in de token; als onze header deviceCode
        anders is → 405. Daarom MOET header deviceCode gelijk zijn aan die van de
        phone-app die de token signeert.
        """
        if self._device_code:
            return self._device_code
        try:
            r = requests.get(f"{self.url}/devicecode", timeout=min(self.timeout, 10))
            r.raise_for_status()
            d = r.json()
            dc = str(d.get("deviceCode", "") or "")
            if dc and dc != "unknown" and not dc.startswith("ERR"):
                self._device_code = dc
                log(f"  deviceCode (bridge): {dc}", C.DIM)
                return dc
        except Exception as e:  # noqa: BLE001
            log(f"  ! bridge deviceCode gagal: {e}", C.Y)
        return "fe54e4426469bb55"  # fallback: cached van bridge

    def sign(self, body_bytes: bytes, typ: int = 1) -> str:
        """Return wToken voor body_bytes EXACT.

        CRITICAL: body moet EXACT bytes die verstuurd gaat worden — re-stringify
        na signing = signature break (server checkt body diff).
        """
        if not self.available:
            return WTOKEN_PASSTHRU
        # body bytes → UTF-8 string (signer side encodes same utf-8)
        payload = body_bytes.decode("utf-8", errors="replace")
        last: Optional[BaseException] = None
        for i in range(max(1, self.retries)):
            try:
                r = requests.post(f"{self.url}/sign",
                                  json={"body": payload, "type": typ},
                                  timeout=self.timeout)
                r.raise_for_status()
                d = r.json()
                if not d.get("ok"):
                    raise RuntimeError(f"signer return ok=false: {d}")
                tok = str(d.get("wToken", ""))
                if not tok or not tok.startswith("000"):
                    raise RuntimeError(f"wToken shape asing: {tok[:40]}")
                return tok
            except Exception as e:  # noqa: BLE001
                last = e
                if i + 1 < max(1, self.retries):
                    time.sleep(1.0)
        self._fail = True
        raise RuntimeError(f"TigerTally signer tidak reachable ({self.url}): {last}")


SIGNER = TigerTallySigner()


class TomoroClient:
    def __init__(self, persona: Persona, *,
                 proxy_pool: Optional[ProxyPool] = None,
                 initial_proxy: Optional[ProxyEntry] = None,
                 max_proxy_attempts: int = PROXY_MAX_ATTEMPTS):
        self.persona = persona
        self.session = requests.Session()
        self.session.headers.update({"Connection": "Keep-Alive", "Accept-Encoding": "gzip"})
        self.token = ""
        self.proxy_pool = proxy_pool
        self.max_proxy_attempts = max_proxy_attempts
        self.current_proxy: Optional[ProxyEntry] = initial_proxy
        # Sticky: gunakan satu proxy konsisten selama satu pendaftaran.
        # Jika initial_proxy tidak diberikan tapi pool ada, ambil sekarang
        # (back-compat untuk pemanggil lama).
        if self.current_proxy is None and proxy_pool and not proxy_pool.empty:
            self.current_proxy = proxy_pool.get_next()

    def _headers(self, extra: Optional[dict[str, str]] = None) -> dict[str, str]:
        device_code = self.persona.device_code
        # WAF: token is gesigned door de phone-app SDK → deviceCode in header
        # MOET gelijk zijn aan die van de bridge (anders 405).
        if USE_SIGNER and SIGNER.available:
            device_code = SIGNER.bridge_device_code() or device_code
        h = {
            "Content-Type": "application/json",
            "token": self.token,
            "revision": REVISION,
            "countryCode": COUNTRY_CODE,
            "appChannel": APP_CHANNEL,
            "appLanguage": APP_LANGUAGE,
            "timeZone": TIMEZONE,
            "deviceCode": device_code,
            "longitude": self.persona.longitude,
            "latitude": self.persona.latitude,
            "ucde": "t698",
            "wToken": WTOKEN_PASSTHRU,
            "Host": "api-service.tomoro-coffee.id",
            "User-Agent": USER_AGENT,
        }
        if extra:
            h.update(extra)
        return h

    def _jitter(self):
        time.sleep(random.randint(JITTER_MIN, JITTER_MAX) / 1000.0)

    def _proxies_for(self, p: Optional[ProxyEntry]) -> Optional[dict[str, str]]:
        return p.to_requests() if p else None

    def _req(self, method: str, path: str, *, params=None, json_body=None,
             extra_headers: Optional[dict[str, str]] = None) -> dict[str, Any]:
        url = f"{BASE_URL}{path}"
        body_bytes = None
        headers = self._headers(extra_headers)
        if json_body is not None:
            body_bytes = json.dumps(json_body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json; charset=UTF-8"
            headers["Content-Length"] = str(len(body_bytes))

        # TigerTally wToken: sign EXACT serde body bytes (app interceptor shape).
        # GET/zonder body → sign empty byte string "". Server WAF flags missing.
        if SIGNER.available:
            sign_input = body_bytes if body_bytes is not None else b""
            headers["wToken"] = SIGNER.sign(sign_input)

        attempts = 0
        max_attempts = (self.max_proxy_attempts if self.proxy_pool and not self.proxy_pool.empty else 1)
        last_exc: Optional[BaseException] = None
        while attempts < max_attempts:
            attempts += 1
            proxies = self._proxies_for(self.current_proxy)
            try:
                r = self.session.request(method, url, params=params, data=body_bytes,
                                         headers=headers, proxies=proxies, timeout=20)
                # request berhasil → tandai proxy ini sehat
                if self.current_proxy:
                    self.proxy_pool.mark_alive(self.current_proxy)  # type: ignore[union-attr]
                try:
                    return r.json()
                except json.JSONDecodeError:
                    raise RuntimeError(
                        f"Non-JSON response from {path}: {r.status_code} {r.text[:300]}"
                    )
            except BaseException as e:  # noqa: BLE001
                last_exc = e
                if self.proxy_pool and self.current_proxy and is_proxy_error(e):
                    # proxy mati → tandai mati, ambil yang berikutnya, retry
                    log(f"  ! proxy mati: {self.current_proxy.raw} ({type(e).__name__}); ganti…", C.Y)
                    self.proxy_pool.mark_dead(self.current_proxy)
                    try:
                        self.current_proxy = self.proxy_pool.get_next()
                    except NoLiveProxyError:
                        raise
                    continue
                raise
        # kehabisan attempts
        if last_exc:
            raise last_exc
        raise RuntimeError(f"Gagal request {path}: tidak ada response.")

    # -- step methods ---------------------------------------------------
    def get_phone_area(self):
        return self._req("GET", "/portal/app/member/getPhoneArea")

    def check_member(self, phone, area):
        return self._req("GET", "/portal/app/member/v2/checkMemberByPhone",
                         params={"phone": phone, "areaCode": area})

    def send_sms(self, phone, area):
        return self._req("GET", "/portal/app/member/sendMessage",
                         params={"phone": phone, "areaCode": area, "verifyChannel": "SMS"},
                         extra_headers={"s": SENDMSG_S_HEADER})

    def verify_sms(self, phone, area, code):
        return self._req("POST", "/portal/app/member/v2/verifySms",
                         json_body={"phoneArea": area, "phone": phone, "verifyCode": code})

    def get_is_show_invite(self):
        return self._req("GET", "/portal/app/member/v2/getIsShowInvite")

    def check_code(self, invite_code, email):
        return self._req("POST", "/portal/app/member/v2/checkCode",
                         json_body={"invitationCode": invite_code, "email": email,
                                    "emailVerifyCode": ""})

    def register(self, *, phone, area, otp, pin, invite_code):
        body = {
            "phoneArea": area, "phone": phone,
            "emailVerifyCode": "", "phoneVerifyCode": otp,
            "email": self.persona.email, "nickname": self.persona.nickname,
            "gender": self.persona.gender, "birth": self.persona.birth,
            "invitationCode": invite_code,
            "password": hashlib.md5(pin.encode()).hexdigest(),
            "channel": APP_CHANNEL, "revision": REVISION,
            "type": 2, "source": "",
        }
        out = self._req("POST", "/portal/app/member/v2/register", json_body=body)
        if out.get("success") and isinstance(out.get("data"), dict):
            tok = out["data"].get("token")
            if tok:
                self.token = tok
        return out

    def coupon_quantity(self):
        return self._req("POST", "/portal/app/coupon/getCouponMemberQuantity",
                         json_body={})

    def coupon_list(self, page=1, size=20):
        return self._req("POST", "/portal/app/coupon/getCouponMemberList",
                         json_body={"pageNo": str(page), "pageSize": str(size)})


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------

HASIL_TXT = ROOT / "hasil.txt"
HASIL_JSON = ROOT / "hasil.json"
LOG_DIR = ROOT / "logs"

HASIL_TXT_HEADER = ["phone", "pin", "expired", "create_date"]

TARGET_VOUCHER_PATTERNS = [
    "50% off any drinks small size",
]


def _norm(s: str) -> str:
    return " ".join((s or "").lower().split())


def pick_target_voucher_expiry(vouchers: list[dict[str, Any]]) -> str:
    for v in vouchers:
        hay = _norm(v.get("name", "")) + " | " + _norm(v.get("desc", ""))
        for pat in TARGET_VOUCHER_PATTERNS:
            if _norm(pat) in hay:
                return v.get("end") or ""
    return ""


def _read_hasil_txt_rows() -> tuple[list[str], list[list[str]]]:
    if not HASIL_TXT.exists():
        return [], []
    with open(HASIL_TXT, encoding="utf-8", newline="") as f:
        reader = csv.reader(f, delimiter="\t", quotechar='"')
        rows = list(reader)
    if not rows:
        return [], []
    return rows[0], rows[1:]


def _write_hasil_txt(rows: list[list[str]]):
    with open(HASIL_TXT, "w", encoding="utf-8", newline="") as f:
        f.write("\t".join(HASIL_TXT_HEADER) + "\r\n")
        for r in rows:
            r = list(r) + [""] * (len(HASIL_TXT_HEADER) - len(r))
            f.write("\t".join(r[:len(HASIL_TXT_HEADER)]) + "\r\n")


def _ensure_new_format():
    header, rows = _read_hasil_txt_rows()
    if not header or header == HASIL_TXT_HEADER:
        return
    col = {name: i for i, name in enumerate(header)}
    new_rows = []
    for r in rows:
        if not r:
            continue
        phone = r[col["phone"]] if "phone" in col and col["phone"] < len(r) else ""
        pin   = r[col["pin"]]   if "pin"   in col and col["pin"]   < len(r) else ""
        exp   = r[col["expired"]]     if "expired" in col and col["expired"] < len(r) else ""
        cdate = r[col["create_date"]] if "create_date" in col and col["create_date"] < len(r) else ""
        new_rows.append([phone, pin, exp, cdate])
    _write_hasil_txt(new_rows)


def upsert_hasil_txt(phone: str, pin: str, expired: str, create_date: str):
    with _FILE_LOCK:
        _ensure_new_format()
        header, rows = _read_hasil_txt_rows()
        new_row = [phone, pin, expired, create_date]
        if not header:
            _write_hasil_txt([new_row])
            return
        replaced = False
        out = []
        for r in rows:
            if r and r[0] == phone:
                out.append(new_row); replaced = True
            else:
                out.append(r)
        if not replaced:
            out.append(new_row)
        _write_hasil_txt(out)


def already_in_txt(phone: str) -> bool:
    with _FILE_LOCK:
        _ensure_new_format()
        _, rows = _read_hasil_txt_rows()
        return any(r and r[0] == phone for r in rows)


def load_hasil_json() -> list[dict[str, Any]]:
    if HASIL_JSON.exists():
        try:
            return json.loads(HASIL_JSON.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []
    return []


def save_hasil_json(records: list[dict[str, Any]]):
    tmp = HASIL_JSON.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(HASIL_JSON)


def upsert_hasil_json(record: dict[str, Any]):
    with _FILE_LOCK:
        records = load_hasil_json()
        records = [r for r in records if r.get("phone") != record.get("phone")]
        records.append(record)
        save_hasil_json(records)


# --- Google Sheets ---
# creds path di-resolve relatif ke ROOT kalau bukan absolute.
_sheets_creds = SHEETS_CREDS_FILE
if _sheets_creds and not Path(_sheets_creds).is_absolute():
    _sheets_creds = str(ROOT / _sheets_creds)

SHEETS = make_sheets_sync(
    enabled=SHEETS_ENABLED,
    creds_path=_sheets_creds,
    spreadsheet_id=SHEETS_SPREADSHEET_ID,
    worksheet_gid=SHEETS_WORKSHEET_GID,
    worksheet_name=SHEETS_WORKSHEET_NAME,
    logger=lambda m: log(f"  [sheets] {m}", C.DIM),
)


def push_to_sheets(phone: str, pin: str, expired: str, create_date: str):
    """Append akun ke Google Sheets. Fail-soft: tidak menggagalkan pendaftaran."""
    if SHEETS is None:
        return
    if SHEETS.append_account(phone, pin, expired, create_date):
        log("  ✓ disimpan ke Google Sheets", C.G)


# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------

class C:
    R = "\033[31m"; G = "\033[32m"; Y = "\033[33m"; B = "\033[34m"
    M = "\033[35m"; Cy = "\033[36m"; DIM = "\033[2m"; END = "\033[0m"


# Lock untuk stdout supaya output dari banyak worker tidak interleave per-character.
_LOG_LOCK = threading.Lock()
# Lock untuk file hasil.txt + hasil.json (read-modify-write race kalau >1 worker).
_FILE_LOCK = threading.Lock()
# Per-thread label (W1/W2/...) supaya log mudah dibaca saat multi-thread.
_LOCAL = threading.local()


def _tag() -> str:
    lbl = getattr(_LOCAL, "label", None)
    return f"[{lbl}] " if lbl else ""


def log(msg: str, color: str = ""):
    line = f"{_tag()}{msg}"
    with _LOG_LOCK:
        print(f"{color}{line}{C.END}" if color else line, flush=True)


# ---------------------------------------------------------------------------
# OTP source abstraction
# ---------------------------------------------------------------------------
#
# Tomoro register flow harus menerima nomor + OTP. Sumbernya bisa:
#   - manual: user input nomor → user input OTP
#   - provider (hero-sms): rent nomor → poll OTP
# Kita bungkus dua-duanya jadi context manager 'OTPSource' supaya
# pipeline registrasi tetap satu baris kode.
# ---------------------------------------------------------------------------

class _ManualSource:
    name = "manual"

    def __init__(self, phone_raw: str, otp_preset: Optional[str] = None):
        self._phone_raw = phone_raw
        self._otp_preset = otp_preset
        self._activation = None  # type: ignore[assignment]

    def acquire_phone(self) -> tuple[str, str]:
        return normalize_phone(self._phone_raw)

    def need_send_sms(self) -> bool:
        # Manual: kita SUDAH minta Tomoro kirim SMS-nya sendiri (lewat sendMessage).
        return True

    def fetch_otp(self) -> str:
        if self._otp_preset:
            return self._otp_preset
        otp = input("  Masukkan OTP yang diterima: ").strip()
        if not otp:
            raise RuntimeError("OTP kosong, dibatalkan.")
        return otp

    def on_success(self): pass
    def on_failure(self, exc: BaseException): pass


class _ProviderSource:
    """Bungkus OTPProvider (hero-sms dst.) jadi sumber nomor + OTP otomatis."""
    def __init__(self, provider: OTPProvider, *, service: str, country: str | int,
                 operator: str, max_price: float,
                 otp_timeout: int, poll_sec: int):
        self.provider = provider
        self.service = service
        self.country = country
        self.operator = operator
        self.max_price = max_price
        self.otp_timeout = otp_timeout
        self.poll_sec = poll_sec
        self._activation: Optional[Activation] = None

    @property
    def name(self) -> str:
        return self.provider.name

    def acquire_phone(self) -> tuple[str, str]:
        log(f"  ▷ rent nomor via {self.provider.name} (service={self.service} country={self.country} maxPrice=${self.max_price})", C.B)
        act = self.provider.get_number(
            service=self.service, country=self.country,
            operator=self.operator, max_price=self.max_price,
        )
        self._activation = act
        log(f"  ✓ nomor disewa: +{act.phone}  (id={act.id} cost=${act.cost} op={act.operator})", C.G)
        # Phone provider format = full international (mis. 6283857426961). Pecah jadi (lokal, area).
        return normalize_phone(act.phone)

    def need_send_sms(self) -> bool:
        # Provider expects target app (Tomoro) yang kirim SMS ke nomor yang disewa.
        # Jadi kita TETAP harus panggil Tomoro sendMessage. Provider cuma menerima OTP-nya.
        return True

    def fetch_otp(self) -> str:
        assert self._activation, "fetch_otp dipanggil sebelum acquire_phone"
        log(f"  … menunggu OTP (timeout {self.otp_timeout}s, poll tiap {self.poll_sec}s)", C.DIM)
        # Catatan: timeout di-set > 125s supaya kalau timeout terjadi,
        # cancel activation langsung diterima HeroSMS (lewat minActivationTime).
        # Tidak ada retry/resend — akun yang OTP-nya tidak masuk dianggap GAGAL,
        # dibatalkan untuk refund, lalu pipeline lanjut ke akun berikutnya.
        code = self.provider.wait_for_otp(
            self._activation.id,
            timeout=self.otp_timeout,
            poll=self.poll_sec,
        )
        log(f"  ✓ OTP diterima: {code}", C.G)
        return code

    def on_success(self):
        if self._activation:
            try:
                self.provider.finalize(self._activation.id)
                log(f"  ✓ activation {self._activation.id} difinalkan", C.DIM)
            except Exception as e:  # noqa: BLE001
                log(f"  ! gagal finalize activation: {e}", C.Y)

    def on_failure(self, exc: BaseException):
        if not self._activation:
            return
        # Coba cancel; kalau early-cancel, tunggu sebentar lalu retry sekali
        for attempt in range(2):
            try:
                self.provider.cancel(self._activation.id)
                log(f"  ✓ activation {self._activation.id} dibatalkan (refund)", C.DIM)
                return
            except HeroSMSError as e:
                if e.title == "EARLY_CANCEL_DENIED" and attempt == 0:
                    wait = (e.info or {}).get("minActivationTime", 130)
                    log(f"  ! cancel ditolak (perlu hold {wait}s), tunggu lalu retry…", C.Y)
                    time.sleep(int(wait) + 5)
                    continue
                log(f"  ! gagal cancel activation: {e}", C.Y)
                return
            except Exception as e:  # noqa: BLE001
                log(f"  ! gagal cancel activation: {e}", C.Y)
                return


# ---------------------------------------------------------------------------
# Proxy precheck
# ---------------------------------------------------------------------------
#
# Tujuan: SEBELUM menyewa nomor (yang memakan saldo OTP), pastikan dulu kita
# punya proxy yang benar-benar bisa reach Tomoro API. Kalau proxy mati / di-block,
# tandai mati & ambil yang berikutnya. Hasilnya = ProxyEntry yang sudah terbukti
# hidup, siap dipakai TomoroClient untuk seluruh request akun ini (sticky).
# ---------------------------------------------------------------------------

def precheck_proxy(pool: Optional[ProxyPool],
                   *, max_tries: int = PROXY_PRECHECK_MAX_TRIES,
                   timeout: int = PROXY_PRECHECK_TIMEOUT,
                   url: str = PROXY_PRECHECK_URL) -> Optional[ProxyEntry]:
    """Validasi proxy berikutnya sampai ketemu yang hidup.

    - pool=None  → return None (mode tanpa proxy).
    - max_tries=0 → scan SELURUH pool (alive_count) sebelum menyerah. Cocok untuk
      pool besar (mis. 150+ proxy) di mana mayoritas mungkin mati.
    - kalau berhasil dapat response 2xx/4xx (server merespon) → proxy dianggap hidup.
    - kalau timeout/connect error/proxy error → tandai mati, coba berikutnya.
    - kehabisan kandidat → raise NoLiveProxyError.
    """
    if pool is None or pool.empty:
        return None

    # 0 = scan semua proxy hidup. Pakai alive_count() supaya skip yang sudah
    # ditandai mati di sesi ini & berhenti tepat saat habis.
    budget = max_tries if max_tries > 0 else max(pool.alive_count(), 1)

    last_exc: Optional[BaseException] = None
    tried = 0
    while tried < budget:
        try:
            entry = pool.get_next()
        except NoLiveProxyError:
            raise
        tried += 1
        try:
            pre_headers = {
                "User-Agent": USER_AGENT, "Connection": "close",
                "token": "", "revision": REVISION,
                "countryCode": COUNTRY_CODE, "appChannel": APP_CHANNEL,
                "appLanguage": APP_LANGUAGE, "timeZone": TIMEZONE,
                "deviceCode": "fce81d75253956c0",
                "longitude": "110.81048599783334", "latitude": "-7.562907060833333",
                "ucde": "t698",
            }
            # WAF vereist wToken — sign empty body (GET). Zonder wordt proxy
            # onterecht als "mat" gemarkeerd (405 challenge).
            if SIGNER.available:
                try:
                    pre_headers["wToken"] = SIGNER.sign(b"")
                except Exception:  # noqa: BLE001 — signer down: fallback plain
                    pass
            r = requests.get(
                url,
                proxies=entry.to_requests(),
                timeout=timeout,
                headers=pre_headers,
            )
            # Server menjawab apapun statusnya = proxy reach destination.
            if r.status_code < 500:
                pool.mark_alive(entry)
                log(f"  ✓ proxy OK: {entry.raw}  (http {r.status_code}, percobaan ke-{tried})", C.G)
                return entry
            log(f"  ! proxy {entry.raw} balas HTTP {r.status_code}, ganti…", C.Y)
            pool.mark_dead(entry)
        except BaseException as e:  # noqa: BLE001
            last_exc = e
            log(f"  ! proxy mati ({tried}/{budget}): {entry.raw} — {type(e).__name__}: {str(e)[:80]}", C.Y)
            pool.mark_dead(entry)
            continue

    raise NoLiveProxyError(
        f"Tidak ada proxy hidup setelah {tried} percobaan precheck"
        + (f" (last: {type(last_exc).__name__})" if last_exc else "")
    )


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def run_register(*, source, pin: str, invite_code: str,
                 proxy_pool: Optional[ProxyPool] = None) -> dict[str, Any]:
    persona = gen_persona()

    # 1) PROXY DULU — sebelum nyentuh saldo OTP. Cari proxy yang sudah terbukti
    #    bisa reach Tomoro API. Kalau proxy_pool=None, lewati (mode no-proxy).
    initial_proxy: Optional[ProxyEntry] = None
    if proxy_pool is not None and not proxy_pool.empty:
        log("→ proxy precheck (sebelum sewa nomor)", C.DIM)
        initial_proxy = precheck_proxy(proxy_pool)

    # 2) Setelah proxy aman → baru sewa nomor (provider) atau minta nomor manual.
    phone, area = source.acquire_phone()
    log(f"\n=== Daftar nomor: +{area}{phone}  pin={pin}  ref={invite_code}  src={source.name} ===", C.Cy)
    log(f"  persona: {persona.nickname}  {persona.email}  gender={persona.gender}  birth={persona.birth}")
    log(f"  device : code={persona.device_code} geo=({persona.latitude},{persona.longitude})", C.DIM)

    if already_in_txt(phone):
        log(f"  ! sudah ada di hasil.txt — entry akan diupdate.", C.Y)

    cli = TomoroClient(persona, proxy_pool=proxy_pool, initial_proxy=initial_proxy)
    if cli.current_proxy:
        log(f"  proxy : {cli.current_proxy.raw}", C.DIM)

    try:
        log("→ /member/getPhoneArea", C.DIM)
        cli.get_phone_area(); cli._jitter()

        log("→ /member/v2/checkMemberByPhone", C.DIM)
        chk = cli.check_member(phone, area)
        if chk.get("data", {}).get("isRegister"):
            raise RuntimeError(f"nomor +{area}{phone} sudah terdaftar di Tomoro.")
        cli._jitter()

        if source.need_send_sms():
            log("→ /member/sendMessage  (kirim OTP via SMS)", C.DIM)
            send = cli.send_sms(phone, area)
            if not send.get("success"):
                raise RuntimeError(f"sendMessage gagal: {send}")
            cli._jitter()

        otp = source.fetch_otp()
        cli._jitter()

        log("→ /member/v2/verifySms", C.DIM)
        vs = cli.verify_sms(phone, area, otp)
        if not vs.get("success"):
            raise RuntimeError(f"verifySms gagal: code={vs.get('code')} msg={vs.get('msg')}")
        cli._jitter()

        log("→ /member/v2/getIsShowInvite", C.DIM)
        cli.get_is_show_invite(); cli._jitter()

        log("→ /member/v2/checkCode", C.DIM)
        cc = cli.check_code(invite_code, persona.email)
        if not cc.get("success"):
            raise RuntimeError(f"checkCode gagal: {cc}")
        cli._jitter()

        log("→ /member/v2/register", C.DIM)
        rg = cli.register(phone=phone, area=area, otp=otp, pin=pin, invite_code=invite_code)
        if not rg.get("success"):
            raise RuntimeError(f"register gagal: code={rg.get('code')} msg={rg.get('msg')}")
        user = rg["data"]
        log(f"  ✓ register OK  accountCode={user.get('accountCode')}", C.G)
        cli._jitter()

        log("→ /coupon/getCouponMemberQuantity", C.DIM)
        qty = cli.coupon_quantity(); cli._jitter()
        log("→ /coupon/getCouponMemberList", C.DIM)
        lst = cli.coupon_list(page=1, size=50)

        vouchers = []
        if lst.get("success") and isinstance(lst.get("data"), dict):
            for rec in lst["data"].get("records", []) or []:
                vouchers.append({
                    "code": rec.get("accountCouponCode"),
                    "couponCode": rec.get("couponCode"),
                    "name": rec.get("couponName"),
                    "desc": rec.get("couponDesc"),
                    "context": rec.get("couponContext"),
                    "start": rec.get("couponActiveStartTime"),
                    "end": rec.get("couponActiveEndTime"),
                    "currency": rec.get("currencyUnit"),
                })
        log(f"  voucher ditemukan: {len(vouchers)} item", C.G)

        target_expired = pick_target_voucher_expiry(vouchers)
        if target_expired:
            log(f"  target voucher (50% OFF small size) expired: {target_expired}", C.G)
        else:
            log("  target voucher (50% OFF small size) tidak ditemukan di akun ini", C.Y)

        create_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        record = {
            "phone": phone,
            "areaCode": area,
            "fullPhone": f"+{area}{phone}",
            "pin": pin,
            "expired": target_expired,
            "create_date": create_date,
            "registeredAt": datetime.now().astimezone().isoformat(timespec="seconds"),
            "accountCode": user.get("accountCode"),
            "nickname": user.get("nickname"),
            "email": user.get("email"),
            "gender": user.get("gender"),
            "birth": user.get("birth"),
            "invitationCode": invite_code,
            "token": user.get("token"),
            "device": {
                "deviceCode": persona.device_code,
                "longitude": persona.longitude,
                "latitude": persona.latitude,
                "imei": persona.imei,
                "pushToken": persona.push_token,
                "advertisingId": persona.advertising_id,
            },
            "otpSource": source.name,
            "proxy": cli.current_proxy.raw if cli.current_proxy else None,
            "couponSummary": qty.get("data") if qty.get("success") else None,
            "vouchers": vouchers,
        }

        upsert_hasil_txt(phone, pin, target_expired, create_date)
        upsert_hasil_json(record)
        push_to_sheets(phone, pin, target_expired, create_date)

        LOG_DIR.mkdir(exist_ok=True)
        log_path = LOG_DIR / f"{phone}_{int(time.time())}.json"
        log_path.write_text(json.dumps({
            "register_response": rg,
            "coupon_quantity": qty,
            "coupon_list": lst,
            "persona": persona.to_log(),
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        log(f"  audit: {log_path.name}", C.DIM)
        log(f"  ✓ disimpan ke hasil.txt + hasil.json", C.G)
        source.on_success()
        return record
    except BaseException as e:
        source.on_failure(e)
        raise


# ---------------------------------------------------------------------------
# Provider helper
# ---------------------------------------------------------------------------

def build_otp_provider(name: str) -> OTPProvider:
    n = name.strip().lower()
    if n in ("hero-sms", "herosms"):
        if not HERO_API_KEY or HERO_API_KEY == "YOUR_KEY_HERE":
            raise RuntimeError("HERO_SMS_API_KEY belum diset di .env")
        return make_provider("hero-sms", api_key=HERO_API_KEY, base_url=HERO_BASE_URL)
    raise RuntimeError(f"OTP provider {name!r} tidak dikenal.")


def build_provider_source(provider: OTPProvider) -> _ProviderSource:
    if isinstance(provider, type(make_provider("hero-sms", api_key="x"))):  # type check pragmatic
        pass
    return _ProviderSource(
        provider=provider,
        service=HERO_SERVICE, country=HERO_COUNTRY,
        operator=HERO_OPERATOR, max_price=HERO_MAX_PRICE,
        otp_timeout=HERO_OTP_TIMEOUT, poll_sec=HERO_POLL_SEC,
    )


# ---------------------------------------------------------------------------
# CLI entry points
# ---------------------------------------------------------------------------

def _interactive_menu() -> dict[str, Any]:
    """Tanya user: provider + jumlah akun + override pin/ref kalau mau."""
    log("\n=== Tomoro Auto-Register — Interaktif ===", C.Cy)

    # OTP provider
    default_prov = OTP_PROVIDER_NAME if OTP_PROVIDER_NAME in ("hero-sms", "manual") else "manual"
    log(f"\n[1] Pilih OTP provider:")
    log(f"    1) hero-sms   (otomatis sewa nomor + ambil OTP)")
    log(f"    2) manual     (Anda input nomor + OTP)")
    raw = input(f"  Pilihan [default: {default_prov}]: ").strip().lower()
    if raw in ("", "1") and default_prov == "hero-sms":
        provider_name = "hero-sms"
    elif raw == "1" or raw == "hero-sms" or raw == "herosms":
        provider_name = "hero-sms"
    elif raw == "2" or raw == "manual":
        provider_name = "manual"
    else:
        provider_name = default_prov

    # Jumlah akun
    if provider_name == "hero-sms":
        log(f"\n[2] Berapa akun BERHASIL yang ingin dibuat? (1-{MAX_BULK_COUNT})")
        log(f"    Catatan: gagal tidak dihitung. Script akan terus retry sampai target tercapai", C.DIM)
        log(f"    (batas keras: target × {BULK_MAX_ATTEMPTS_MULT} percobaan biar saldo tidak habis).", C.DIM)
        raw = input(f"  Jumlah [default: {DEFAULT_BULK_COUNT}]: ").strip()
        try:
            count = int(raw) if raw else DEFAULT_BULK_COUNT
        except ValueError:
            count = DEFAULT_BULK_COUNT
        if count < 1: count = 1
        if count > MAX_BULK_COUNT:
            log(f"  ! dibatasi ke MAX_BULK_COUNT={MAX_BULK_COUNT}", C.Y)
            count = MAX_BULK_COUNT
    else:
        count = 1
        log("\n[2] Mode manual: 1 akun saja per run.", C.DIM)

    # Worker / thread
    if provider_name == "hero-sms" and count > 1:
        log(f"\n[3] Berapa thread paralel? (1-{MAX_WORKER_THREADS})")
        log(f"    Tiap worker punya proxy + persona sendiri, bekerja serentak.", C.DIM)
        raw = input(f"  Worker [default: {WORKER_THREADS}]: ").strip()
        try:
            workers = int(raw) if raw else WORKER_THREADS
        except ValueError:
            workers = WORKER_THREADS
        if workers < 1:
            workers = 1
        if workers > MAX_WORKER_THREADS:
            log(f"  ! dibatasi ke MAX_WORKER_THREADS={MAX_WORKER_THREADS}", C.Y)
            workers = MAX_WORKER_THREADS
        if workers > count:
            workers = count
    else:
        workers = 1

    # PIN / ref override (opsional)
    pin_idx = 4 if (provider_name == "hero-sms" and count > 1) else 3
    pin = input(f"\n[{pin_idx}] PIN [default {DEFAULT_PIN}]: ").strip() or DEFAULT_PIN
    ref = input(f"[{pin_idx + 1}] Ref code [default {DEFAULT_REF}]: ").strip() or DEFAULT_REF

    return {"provider": provider_name, "count": count, "workers": workers, "pin": pin, "ref": ref}


def _print_summary(results: list[tuple[str, Optional[str], Optional[str]]]):
    ok = [r for r in results if r[1] == "OK"]
    fail = [r for r in results if r[1] not in ("OK", "INTERRUPTED")]
    log(f"\n=== RINGKASAN: berhasil={len(ok)}  gagal={len(fail)}  total percobaan={len(results)} ===", C.Cy)
    for phone, status, msg in results:
        if status == "OK":
            log(f"  ✓ +{phone}  {msg or ''}", C.G)
        else:
            log(f"  ✗ {phone or '?'}  {status}: {msg or ''}", C.R)


def main():
    p = argparse.ArgumentParser(description="Tomoro auto-register.")
    p.add_argument("--phone", help="(manual) nomor target — kalau diisi, paksa mode manual")
    p.add_argument("--pin", default=None, help=f"PIN (default dari .env: {DEFAULT_PIN})")
    p.add_argument("--ref", default=None, help=f"kode referral (default dari .env: {DEFAULT_REF})")
    p.add_argument("--otp", help="(manual) OTP yang sudah di tangan")
    p.add_argument("--otp-provider", choices=["manual", "hero-sms"], default=None,
                   help="paksa provider tertentu (override .env)")
    p.add_argument("--count", type=int, default=None,
                   help="jumlah akun untuk dibuat (mode bulk dengan provider)")
    p.add_argument("--workers", type=int, default=None,
                   help=f"jumlah thread paralel (default {WORKER_THREADS}, max {MAX_WORKER_THREADS})")
    p.add_argument("--no-proxy", action="store_true", help="paksa jalan tanpa proxy")
    p.add_argument("--seed", type=int, help="seed RNG (reproduksi persona; jarang dipakai)")
    args = p.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    # Tentukan apakah harus interaktif
    interactive = (args.phone is None and args.count is None and args.otp_provider is None)

    if interactive:
        choice = _interactive_menu()
        provider_name = choice["provider"]
        count = choice["count"]
        workers = choice["workers"]
        pin = choice["pin"]
        invite = choice["ref"]
    else:
        provider_name = (args.otp_provider or OTP_PROVIDER_NAME or "manual")
        if args.phone is not None:
            provider_name = "manual"
            count = 1
        else:
            count = args.count if args.count is not None else 1
        pin = args.pin or DEFAULT_PIN
        invite = args.ref or DEFAULT_REF
        workers = args.workers if args.workers is not None else WORKER_THREADS

    # Manual mode tidak bisa multi-thread (butuh stdin per akun).
    if provider_name == "manual":
        workers = 1
    workers = max(1, min(workers, MAX_WORKER_THREADS, count))

    # Proxy
    pool: Optional[ProxyPool] = None
    if USE_PROXY and not args.no_proxy:
        pool = ProxyPool.from_file(ROOT / PROXY_FILE)
        if pool.empty:
            log(f"  ! {PROXY_FILE} kosong / tidak ada — jalan tanpa proxy.", C.Y)
            pool = None
        else:
            log(f"  proxy: {len(pool)} entry dari {PROXY_FILE} (round-robin)", C.B)
    else:
        log("  proxy: dimatikan (USE_PROXY=0 atau --no-proxy)", C.DIM)

    # Bangun OTP provider sekali (kalau bukan manual)
    provider: Optional[OTPProvider] = None
    if provider_name != "manual":
        try:
            provider = build_otp_provider(provider_name)
            bal = provider.get_balance()
            log(f"  {provider.name}: balance ${bal:.4f}", C.B)
            if provider_name == "hero-sms":
                # Cek harga + stok sekali di awal supaya gagal cepat
                try:
                    pi = provider.get_prices(HERO_SERVICE, HERO_COUNTRY)  # type: ignore[attr-defined]
                    if pi:
                        log(f"  {provider.name}: harga ${pi.get('cost')}  stok={pi.get('count')}", C.DIM)
                except Exception:  # noqa: BLE001
                    pass
        except Exception as e:  # noqa: BLE001
            log(f"  [FAIL] init provider: {e}", C.R)
            sys.exit(1)

    # Eksekusi
    # Target = sukses sebanyak `count` akun. Kegagalan tidak dihitung;
    # script akan terus mencoba hingga target tercapai ATAU mencapai
    # batas maksimal percobaan (target * BULK_MAX_ATTEMPTS_MULT).
    results: list[tuple[str, Optional[str], Optional[str]]] = []
    target = count
    # Manual mode tidak masuk akal di-loop — 1 nomor input = 1 attempt.
    max_attempts = target if provider is None else max(target, target * BULK_MAX_ATTEMPTS_MULT)

    if workers > 1:
        log(f"  workers: {workers} thread paralel", C.B)
    else:
        log(f"  workers: single-thread", C.DIM)

    # Shared state untuk koordinasi antar worker.
    state_lock = threading.Lock()
    success = 0
    attempts = 0
    stop_flag = threading.Event()

    def _claim_attempt() -> Optional[int]:
        """Atomik: kalau target belum tercapai & belum exceed max_attempts,
        ambil nomor percobaan. Return None kalau worker harus berhenti."""
        nonlocal attempts
        with state_lock:
            if stop_flag.is_set():
                return None
            if success >= target:
                return None
            if attempts >= max_attempts:
                return None
            attempts += 1
            return attempts

    def _record_success(rec: dict[str, Any]):
        nonlocal success
        with state_lock:
            success += 1
            results.append((f"{rec['areaCode']}{rec['phone']}", "OK",
                            f"voucher={len(rec['vouchers'])} expired={rec.get('expired') or '-'}"))

    def _record_failure(label: str, msg: str):
        with state_lock:
            results.append((label, "FAIL", msg))

    def _worker(worker_id: int):
        _LOCAL.label = f"W{worker_id}"
        try:
            while True:
                attempt_no = _claim_attempt()
                if attempt_no is None:
                    return
                with state_lock:
                    cur_success = success
                log(f"\n────────── percobaan {attempt_no}  ▸  sukses {cur_success}/{target} ──────────", C.M)

                # Bangun source untuk akun ini (manual hanya jalan di worker tunggal).
                if provider is None:
                    phone_in = args.phone or input("Masukkan nomor (contoh 83878107651): ").strip()
                    if not phone_in:
                        log("Nomor tidak boleh kosong.", C.R)
                        _record_failure("?", "nomor kosong")
                        continue
                    src = _ManualSource(phone_in, otp_preset=args.otp)
                else:
                    src = build_provider_source(provider)

                try:
                    rec = run_register(source=src, pin=pin, invite_code=invite, proxy_pool=pool)
                    _record_success(rec)
                except KeyboardInterrupt:
                    log("\n[!] dibatalkan user", C.Y)
                    with state_lock:
                        results.append(("?", "INTERRUPTED", ""))
                    stop_flag.set()
                    return
                except NoLiveProxyError as e:
                    log(f"\n[FATAL] {e} — semua worker dihentikan.", C.R)
                    _record_failure("?", str(e))
                    stop_flag.set()
                    return
                except Exception as e:  # noqa: BLE001
                    log(f"\n[FAIL] {e}", C.R)
                    _record_failure("?", str(e))

                # Delay sebelum percobaan berikutnya (per-worker, kecuali sudah selesai).
                with state_lock:
                    keep_going = success < target and attempts < max_attempts and not stop_flag.is_set()
                if keep_going:
                    d = random.randint(BULK_DELAY_MIN, BULK_DELAY_MAX)
                    log(f"  ⏳ tunggu {d}s sebelum percobaan berikutnya…", C.DIM)
                    time.sleep(d)
        finally:
            _LOCAL.label = None

    if workers == 1:
        _worker(1)
    else:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="reg") as ex:
            futures = [ex.submit(_worker, i + 1) for i in range(workers)]
            try:
                for f in as_completed(futures):
                    f.result()
            except KeyboardInterrupt:
                log("\n[!] Ctrl-C — menunggu worker selesai…", C.Y)
                stop_flag.set()
                for f in futures:
                    try:
                        f.result(timeout=30)
                    except Exception:  # noqa: BLE001
                        pass

    if success < target and attempts >= max_attempts:
        log(f"\n  ! batas maksimum percobaan tercapai ({max_attempts}). "
            f"Hanya {success}/{target} akun yang berhasil.", C.Y)

    _print_summary(results)
    sys.exit(0 if success >= target else 1)


if __name__ == "__main__":
    main()
