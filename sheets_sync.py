"""
Google Sheets sync — append akun berhasil ke spreadsheet.

Skema baris (mulai kolom A):
  A : (kosong)
  B : phone        (nomor lokal tanpa kode, mis. 8123...)
  C : pin          (selalu text 6 digit, mis. "000000")
  D : expired      (tanggal expired voucher)
  E : "Fresh"      (status, selalu)
  F : create_date  (tanggal buat akun)

Desain:
  - Lazy init: client gspread baru dibuat saat append pertama.
  - Fail-soft: kalau Sheets error / kredensial salah, account creation TIDAK
    ikut gagal. Error hanya di-log via callback.
  - Thread-safe: append diserialkan dengan lock (banyak worker paralel).
  - value_input_option=RAW → "000000" tetap tersimpan sebagai text, bukan 0.
"""
from __future__ import annotations

import threading
from typing import Callable, Optional

_SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive",
]


class SheetsSync:
    def __init__(
        self,
        creds_path: str,
        spreadsheet_id: str,
        worksheet_gid: Optional[int] = None,
        worksheet_name: str = "",
        logger: Optional[Callable[[str], None]] = None,
    ):
        self.creds_path = creds_path
        self.spreadsheet_id = spreadsheet_id
        self.worksheet_gid = worksheet_gid
        self.worksheet_name = worksheet_name
        self._log = logger or (lambda _m: None)
        self._lock = threading.Lock()
        self._ws = None
        self._init_failed = False

    def _ensure_ws(self):
        if self._ws is not None or self._init_failed:
            return
        try:
            import gspread
            from google.oauth2.service_account import Credentials

            creds = Credentials.from_service_account_file(self.creds_path, scopes=_SCOPES)
            gc = gspread.authorize(creds)
            sh = gc.open_by_key(self.spreadsheet_id)
            if self.worksheet_name:
                self._ws = sh.worksheet(self.worksheet_name)
            elif self.worksheet_gid is not None:
                self._ws = sh.get_worksheet_by_id(self.worksheet_gid)
            else:
                self._ws = sh.sheet1
            self._log(f"Sheets terhubung: {self._ws.title}")
        except Exception as e:
            self._init_failed = True
            self._log(f"Sheets init GAGAL ({type(e).__name__}: {e}) — sync dilewati")

    def append_account(self, phone: str, pin: str, expired: str, create_date: str) -> bool:
        """Append satu baris. Return True kalau sukses. Tidak pernah raise."""
        # PIN selalu text 6 digit.
        pin_text = str(pin or "").zfill(6)[:6]
        row = ["", str(phone), pin_text, str(expired or ""), "Fresh", str(create_date or "")]
        with self._lock:
            self._ensure_ws()
            if self._ws is None:
                return False
            try:
                self._ws.append_row(
                    row,
                    value_input_option="RAW",
                    insert_data_option="INSERT_ROWS",
                    table_range="A1",
                )
                return True
            except Exception as e:
                self._log(f"Sheets append GAGAL ({type(e).__name__}: {e})")
                return False


def make_sheets_sync(
    enabled: bool,
    creds_path: str,
    spreadsheet_id: str,
    worksheet_gid: Optional[int],
    worksheet_name: str,
    logger: Optional[Callable[[str], None]] = None,
) -> Optional[SheetsSync]:
    if not enabled or not creds_path or not spreadsheet_id:
        return None
    return SheetsSync(creds_path, spreadsheet_id, worksheet_gid, worksheet_name, logger)
