"""Modular security rule helpers for MailMind.

The public security classifier remains services.spam_detection_service.detect_spam.
Category-specific rule families live here so they can be audited and regression-
tested independently without changing the provider-neutral classifier contract.
"""
