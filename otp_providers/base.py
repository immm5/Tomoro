"""Abstract base untuk OTP/SMS rental providers."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class Activation:
    """Tiket sewa nomor dari provider."""
    id: str                       # provider-side activation id (selalu string)
    phone: str                    # full international tanpa '+', mis. '6283857426961'
    country_code: str             # phone country prefix, mis. '62'
    cost: float                   # biaya USD
    operator: Optional[str] = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def local_phone(self) -> str:
        """Nomor lokal tanpa country prefix.
        '6283857426961' (cc=62) -> '83857426961'.
        """
        if self.country_code and self.phone.startswith(self.country_code):
            return self.phone[len(self.country_code):]
        return self.phone


class OTPProvider(ABC):
    """Kontrak abstrak untuk semua SMS rental vendor."""
    name: str = "base"

    @abstractmethod
    def get_balance(self) -> float: ...

    @abstractmethod
    def get_number(self, *, service: str, country: str | int,
                   operator: str = "any",
                   max_price: Optional[float] = None) -> Activation: ...

    @abstractmethod
    def wait_for_otp(self, activation_id: str, *,
                     timeout: int = 600, poll: int = 5) -> str: ...

    @abstractmethod
    def request_resend(self, activation_id: str) -> None: ...

    @abstractmethod
    def finalize(self, activation_id: str) -> None: ...

    @abstractmethod
    def cancel(self, activation_id: str) -> None: ...
