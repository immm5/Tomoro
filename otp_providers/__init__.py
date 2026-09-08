"""Pluggable OTP/SMS rental providers.

Tambah vendor baru:
    1. Buat file otp_providers/<vendor>.py dengan class turunan OTPProvider.
    2. Daftarkan di _REGISTRY di bawah.
Tidak perlu ubah call site lain (tomoro_reg.py tetap pakai make_provider()).
"""
from __future__ import annotations
from typing import Type

from .base import OTPProvider, Activation
from .hero_sms import HeroSMSProvider

_REGISTRY: dict[str, Type[OTPProvider]] = {
    "hero-sms": HeroSMSProvider,
    "herosms":  HeroSMSProvider,  # alias
}


def make_provider(name: str, **kwargs) -> OTPProvider:
    key = (name or "").strip().lower()
    if key not in _REGISTRY:
        raise KeyError(
            f"OTP provider {name!r} belum terdaftar. "
            f"Tersedia: {sorted(set(_REGISTRY))}"
        )
    return _REGISTRY[key](**kwargs)


__all__ = ["OTPProvider", "Activation", "HeroSMSProvider", "make_provider"]
