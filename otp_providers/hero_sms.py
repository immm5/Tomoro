"""HeroSMS provider — sms-activate-style handler_api.php protocol.

Verified live API May 2026:
  Base URL: https://hero-sms.com/stubs/handler_api.php
  Country 6 = Indonesia
  Auth: ?api_key=...
"""
from __future__ import annotations

import time
from typing import Any, Optional

import requests

from .base import OTPProvider, Activation


class HeroSMSError(RuntimeError):
    """Error terstruktur dari hero-sms (BAD_KEY, NO_NUMBERS, NO_BALANCE, dst.)."""
    def __init__(self, title: str, details: str = "", info: Optional[dict] = None):
        self.title = title
        self.details = details
        self.info = info or {}
        super().__init__(f"{title}: {details}" if details else title)


class HeroSMSProvider(OTPProvider):
    name = "hero-sms"

    def __init__(self, api_key: str,
                 base_url: str = "https://hero-sms.com/stubs/handler_api.php",
                 session: Optional[requests.Session] = None,
                 timeout: int = 20):
        if not api_key:
            raise ValueError("HeroSMS api_key wajib diisi")
        self.api_key = api_key
        self.base_url = base_url
        self.timeout = timeout
        self.s = session or requests.Session()

    # ------------------------------------------------------------------
    # internal
    # ------------------------------------------------------------------
    def _call(self, action: str, **params) -> Any:
        q = {"api_key": self.api_key, "action": action}
        for k, v in params.items():
            if v is not None and v != "":
                q[k] = v
        r = self.s.get(self.base_url, params=q, timeout=self.timeout)
        text = r.text.strip()

        # Plain-text OK responses
        if text.startswith(("ACCESS_", "STATUS_")):
            return text

        # Coba JSON
        try:
            data = r.json()
        except ValueError:
            raise RuntimeError(
                f"HeroSMS unexpected response (HTTP {r.status_code}): {text[:200]}"
            )

        # Error envelope: {"title": "...", "details": "...", "info": {...}}
        if isinstance(data, dict) and "title" in data and "details" in data:
            raise HeroSMSError(
                title=str(data.get("title")),
                details=str(data.get("details", "")),
                info=data.get("info") if isinstance(data.get("info"), dict) else None,
            )
        return data

    # ------------------------------------------------------------------
    # API
    # ------------------------------------------------------------------
    def get_balance(self) -> float:
        out = self._call("getBalance")
        if isinstance(out, str) and out.startswith("ACCESS_BALANCE:"):
            return float(out.split(":", 1)[1])
        raise RuntimeError(f"getBalance: jawaban tidak terduga: {out!r}")

    def get_prices(self, service: str, country: str | int) -> dict[str, Any]:
        """Cek harga + stok untuk service tertentu di sebuah negara.
        Return: {'cost': 0.02, 'count': 26795, 'physicalCount': 26595} atau {} kalau tidak ada.
        """
        out = self._call("getPrices", service=service, country=country)
        if isinstance(out, dict):
            country_block = out.get(str(country)) or out.get(country, {})
            if isinstance(country_block, dict):
                svc = country_block.get(service)
                if isinstance(svc, dict):
                    return svc
        return {}

    def get_number(self, *, service: str, country: str | int,
                   operator: str = "any",
                   max_price: Optional[float] = None) -> Activation:
        # 'any' di HeroSMS = jangan kirim parameter operator sama sekali
        op_param = None if (not operator or operator.lower() == "any") else operator
        out = self._call(
            "getNumberV2",
            service=service,
            country=country,
            operator=op_param,
            maxPrice=max_price,
        )
        if not isinstance(out, dict) or "activationId" not in out:
            raise RuntimeError(f"getNumberV2 unexpected: {out!r}")
        return Activation(
            id=str(out["activationId"]),
            phone=str(out["phoneNumber"]),
            country_code=str(out.get("countryPhoneCode") or ""),
            cost=float(out.get("activationCost") or 0.0),
            operator=out.get("activationOperator"),
            raw=out,
        )

    def get_status(self, activation_id: str) -> dict[str, Any]:
        """V2: {'verificationType':0,'sms':{'code':...,'text':...} | None,'call':...}"""
        out = self._call("getStatusV2", id=activation_id)
        return out if isinstance(out, dict) else {"raw": out}

    def wait_for_otp(self, activation_id: str, *,
                     timeout: int = 600, poll: int = 5) -> str:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                st = self.get_status(activation_id)
            except HeroSMSError as e:
                # STATUS_CANCEL atau activation tidak ada lagi
                if e.title in ("BAD_STATUS", "ACTIVATION_NOT_FOUND", "STATUS_CANCEL"):
                    raise
                # error transient lain → tunggu poll berikutnya
                st = {}
            sms = st.get("sms") if isinstance(st, dict) else None
            if isinstance(sms, dict):
                code = sms.get("code")
                if code:
                    return str(code)
            time.sleep(poll)
        raise TimeoutError(
            f"OTP timeout setelah {timeout}s untuk activation {activation_id}"
        )

    def request_resend(self, activation_id: str) -> None:
        self._call("setStatus", id=activation_id, status=3)

    def finalize(self, activation_id: str) -> None:
        self._call("setStatus", id=activation_id, status=6)

    def cancel(self, activation_id: str) -> None:
        """Cancel + refund. Catatan: gagal dengan EARLY_CANCEL_DENIED kalau
        dipanggil < 120 detik setelah getNumber. Caller harus retry kalau perlu."""
        self._call("setStatus", id=activation_id, status=8)

    # Bonus: list active rentals untuk recovery setelah crash
    def get_active_activations(self) -> list[dict[str, Any]]:
        out = self._call("getActiveActivations")
        if isinstance(out, dict) and out.get("status") == "success":
            data = out.get("data")
            if isinstance(data, list):
                return data
        return []
