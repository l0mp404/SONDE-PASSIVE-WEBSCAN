"""Sonde — audit de sécurité web + email."""

__version__ = "0.1.0"
# Les valeurs d'en-tête HTTP doivent rester ASCII (httpx refuse « é »).
USER_AGENT = f"Sonde/{__version__} (passive security audit)"
