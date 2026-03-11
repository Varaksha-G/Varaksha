"""Varaksha V2 — services package."""

import re as _re


def mask_vpa(vpa: str) -> str:
    """
    Display-layer masking for phone-number VPAs.

    Per DPDP Act 2023 §2(t) mobile numbers are personal data; per NPCI UPI
    Procedural Guidelines PSPs must mask phone-number VPAs in any UI or log
    that is not under the VPA owner's direct control.

    This function is the Python equivalent of the frontend maskVpa() helper
    in frontend/app/live/page.tsx.

    Examples
    --------
    >>> mask_vpa("9876543210@ybl")
    '98****10@ybl'
    >>> mask_vpa("ravi.kumar@axisbank")
    'ravi.kumar@axisbank'
    >>> mask_vpa("98****10@ybl")   # already masked — no-op
    '98****10@ybl'
    """
    if "@" not in vpa:
        return vpa
    handle, bank = vpa.split("@", 1)
    if _re.fullmatch(r"\d{10,}", handle):
        return f"{handle[:2]}****{handle[-2:]}@{bank}"
    return vpa
