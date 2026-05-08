"""Disposable / throwaway email provider list.

The full canonical list lives at:
  https://github.com/disposable-email-domains/disposable-email-domains

We vendor the most common providers here (about ~80 domains covering the
mass-majority of throwaway addresses you'll see in the wild). To extend:
either add to this set, or load from a downloaded copy of the canonical list.
"""
from __future__ import annotations


# Subset focused on what's commonly seen in fraud/test signups.
# Lowercase for direct membership checks.
DISPOSABLE_DOMAINS: frozenset[str] = frozenset({
    # Mainstream throwaway services
    "mailinator.com",
    "guerrillamail.com", "guerrillamail.biz", "guerrillamail.de", "guerrillamail.info",
    "guerrillamail.net", "guerrillamail.org", "sharklasers.com", "spam4.me",
    "10minutemail.com", "10minutemail.net", "20minutemail.com",
    "tempmail.com", "tempmail.org", "temp-mail.org", "tempmail.net", "tempmail.ninja",
    "trashmail.com", "trashmail.net", "trashmail.org",
    "yopmail.com", "yopmail.fr", "yopmail.net",
    "throwawaymail.com", "throwaway.email",
    "maildrop.cc",
    "fakeinbox.com",
    "getnada.com", "nada.email",
    "mohmal.com",
    "discard.email", "discardmail.com",
    "mailnesia.com",
    "mintemail.com",
    "spamgourmet.com",
    "mytemp.email",
    "tempinbox.com",
    "deadaddress.com",
    "mailcatch.com",
    "spambox.us",
    "fakemail.fr",
    "tempemail.co", "tempemail.com",
    "emailondeck.com",
    "moakt.com",
    "armyspy.com",
    "cuvox.de",
    "dayrep.com",
    "einrot.com",
    "fleckens.hu",
    "gustr.com",
    "jourrapide.com",
    "rhyta.com",
    "superrito.com",
    "teleworm.us",
    "33mail.com",
    "0815.ru",
    "mvrht.com",
    "harakirimail.com",
    "incognitomail.org",
    "mailfreeway.com",
    "spamavert.com",
    "spamday.com",
    "spamex.com",
    "spaml.com", "spaml.de",
    "wegwerfmail.de", "wegwerfmail.net", "wegwerfmail.org",
    "tmpmail.org", "tmpmail.net",
    "byom.de",
    "dropmail.me",
    "mailhog.io",
    "kasmail.com",
    "anonymbox.com",
    "binkmail.com",
    "bofthew.com",
    "bobmail.info",
    "boximail.com",
    "fakemailgenerator.com",
    "tempr.email",
    "luxusmail.org",
    "nbox.notif.me",
    "tempemail.net",
    "burnermail.io",
    "minutebox.com",
    "anonemail.de",
    "mailme.lv",
    "fastmail.fm",  # actually legit but often abused — leave commented
})


def is_disposable(domain: str) -> bool:
    """Case-insensitive membership check."""
    return domain.strip().lower() in DISPOSABLE_DOMAINS
