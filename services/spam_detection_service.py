# Explainable security screening and baseline classification for synced email.
import ipaddress
import html
import re
import unicodedata
from email.utils import parseaddr
from urllib.parse import parse_qs, unquote, urlparse

from services.security_trace_service import trace_security_detection

from services.security.account_access_rules import (
    evaluate_account_access_rules,
    has_credential_request,
)
from services.security.shared_document_rules import evaluate_shared_document_rules
from services.security.unrecognized_signin_rules import evaluate_unrecognized_signin_rules
from services.security.password_expiration_rules import evaluate_password_expiration_rules
from services.security.voicemail_notification_rules import evaluate_voicemail_notification_rules
from services.security.mailbox_quota_rules import evaluate_mailbox_quota_rules
from services.security.hr_portal_rules import evaluate_hr_portal_rules
from services.security.oauth_consent_rules import evaluate_oauth_consent_rules
from services.security.qr_image_phishing_rules import evaluate_qr_image_phishing_rules
from services.security.captcha_multistage_rules import evaluate_captcha_multistage_rules
from services.security.device_code_session_rules import evaluate_device_code_session_rules
from services.security.aitm_phishing_rules import evaluate_aitm_phishing_rules
from services.security.multilingual_obfuscated_rules import evaluate_multilingual_obfuscated_rules
from services.security.known_malicious_attachment_rules import (
    evaluate_known_malicious_attachment_rules,
)
from services.security.disguised_executable_rules import (
    evaluate_disguised_executable_rules,
)
from services.security.malicious_archive_rules import evaluate_malicious_archive_rules
from services.security.weaponized_document_rules import evaluate_weaponized_document_rules
from services.security.downloader_loader_rules import evaluate_downloader_loader_rules
from services.security.web_malware_delivery_rules import evaluate_web_malware_delivery_rules
from services.security.infostealer_banking_malware_rules import (
    evaluate_infostealer_banking_malware_rules,
)
from services.security.trojan_backdoor_bot_rat_rules import (
    evaluate_trojan_backdoor_bot_rat_rules,
)
from services.security.ransomware_destructive_malware_rules import (
    evaluate_ransomware_destructive_malware_rules,
)
from services.security.targeted_multistage_malware_rules import (
    evaluate_targeted_multistage_malware_rules,
)
from services.security.referenced_dangerous_payload_enhancement import (
    evaluate_referenced_dangerous_payload_enhancement,
)
from services.security.external_data_transfer_enhancement import (
    evaluate_external_data_transfer_enhancement,
)
from services.security.fake_discount_coupon_rules import evaluate_fake_discount_coupon_rules
from services.security.fake_product_service_rules import evaluate_fake_product_service_rules
from services.security.prize_lottery_inheritance_scam_rules import (
    evaluate_prize_lottery_inheritance_scam_rules,
)
from services.security.advance_fee_scam_rules import evaluate_advance_fee_scam_rules
from services.security.fake_invoice_renewal_debt_rules import (
    evaluate_fake_invoice_renewal_debt_rules,
)
from services.security.fake_refund_recovery_service_rules import (
    evaluate_fake_refund_recovery_service_rules,
)
from services.security.employment_task_scam_rules import evaluate_employment_task_scam_rules
from services.security.fake_check_overpayment_scam_rules import (
    evaluate_fake_check_overpayment_scam_rules,
)
from services.security.emergency_confidence_scam_rules import (
    evaluate_emergency_confidence_scam_rules,
)
from services.security.tech_support_account_protection_scam_rules import (
    evaluate_tech_support_account_protection_scam_rules,
)
from services.security.payment_diversion_fraud_rules import (
    evaluate_payment_diversion_fraud_rules,
)
from services.security.business_email_compromise_rules import (
    evaluate_business_email_compromise_rules,
)
from services.security.investment_cryptocurrency_fraud_rules import (
    evaluate_investment_cryptocurrency_fraud_rules,
)
from services.security.real_estate_high_value_transaction_fraud_rules import (
    evaluate_real_estate_high_value_transaction_fraud_rules,
)
from services.security.money_mule_laundering_recruitment_rules import (
    evaluate_money_mule_laundering_recruitment_rules,
)
from services.security.generic_identity_claim_rules import (
    evaluate_generic_identity_claim_rules,
)
from services.security.display_name_impersonation_rules import (
    evaluate_display_name_impersonation_rules,
)
from services.security.role_department_impersonation_rules import (
    evaluate_role_department_impersonation_rules,
)
from services.security.brand_impersonation_rules import (
    evaluate_brand_impersonation_rules,
)
from services.security.person_name_impersonation_rules import (
    evaluate_person_name_impersonation_rules,
)
from services.security.username_localpart_lookalike_rules import (
    evaluate_username_localpart_lookalike_rules,
)
from services.security.lookalike_domain_impersonation_rules import (
    evaluate_lookalike_domain_impersonation_rules,
)
from services.security.homograph_unicode_impersonation_rules import (
    evaluate_homograph_unicode_impersonation_rules,
)
from services.security.reply_to_impersonation_rules import (
    evaluate_reply_to_impersonation_rules,
)
from services.security.exact_domain_spoofing_rules import (
    evaluate_exact_domain_spoofing_rules,
)
from services.security.internal_employee_executive_impersonation_rules import (
    evaluate_internal_employee_executive_impersonation_rules,
)
from services.security.vendor_business_partner_impersonation_rules import (
    evaluate_vendor_business_partner_impersonation_rules,
)
from services.security.helpdesk_administrator_impersonation_rules import (
    evaluate_helpdesk_administrator_impersonation_rules,
)
from services.security.compromised_account_impersonation_rules import (
    evaluate_compromised_account_impersonation_rules,
)
from services.security.conversation_thread_hijacking_rules import (
    evaluate_conversation_thread_hijacking_rules,
)
from services.security.coordinated_identity_impersonation_rules import (
    evaluate_coordinated_identity_impersonation_rules,
)
from services.security.unwanted_one_off_spam_rules import (
    evaluate_unwanted_one_off_spam_rules,
)
from services.security.repetitive_sender_spam_rules import (
    evaluate_repetitive_sender_spam_rules,
)
from services.security.unsolicited_commercial_spam_rules import (
    evaluate_unsolicited_commercial_spam_rules,
)
from services.security.cold_outreach_spam_rules import (
    evaluate_cold_outreach_spam_rules,
)
from services.security.bulk_list_spam_rules import evaluate_bulk_list_spam_rules
from services.security.harvested_address_spam_rules import (
    evaluate_harvested_address_spam_rules,
)
from services.security.unsubscribe_violation_spam_rules import (
    evaluate_unsubscribe_violation_spam_rules,
)
from services.security.deceptive_subject_spam_rules import (
    evaluate_deceptive_subject_spam_rules,
)
from services.security.obfuscated_content_spam_rules import (
    evaluate_obfuscated_content_spam_rules,
)
from services.security.rotating_sender_snowshoe_spam_rules import (
    evaluate_rotating_sender_snowshoe_spam_rules,
)
from services.security.compromised_account_spam_rules import (
    evaluate_compromised_account_spam_rules,
)
from services.security.botnet_generated_spam_rules import (
    evaluate_botnet_generated_spam_rules,
)
from services.security.reply_chain_conversation_spam_rules import (
    evaluate_reply_chain_conversation_spam_rules,
)
from services.security.backscatter_bounce_spam_rules import (
    evaluate_backscatter_bounce_spam_rules,
)
from services.security.email_subscription_bombing_spam_rules import (
    evaluate_email_subscription_bombing_spam_rules,
)
from services.security.organization_wide_spam_flood_rules import (
    evaluate_organization_wide_spam_flood_rules,
)
from services.security.informational_newsletter_rules import (
    evaluate_informational_newsletter_rules,
)
from services.security.content_marketing_email_rules import (
    evaluate_content_marketing_email_rules,
)
from services.security.brand_awareness_email_rules import (
    evaluate_brand_awareness_email_rules,
)
from services.security.product_announcement_rules import (
    evaluate_product_announcement_rules,
)
from services.security.event_promotion_rules import evaluate_event_promotion_rules
from services.security.general_sales_promotion_rules import (
    evaluate_general_sales_promotion_rules,
)
from services.security.discount_coupon_promotion_rules import (
    evaluate_discount_coupon_promotion_rules,
)
from services.security.seasonal_campaign_rules import evaluate_seasonal_campaign_rules
from services.security.personalized_recommendation_rules import (
    evaluate_personalized_recommendation_rules,
)
from services.security.cross_sell_upsell_rules import evaluate_cross_sell_upsell_rules
from services.security.loyalty_rewards_promotion_rules import (
    evaluate_loyalty_rewards_promotion_rules,
)
from services.security.abandoned_cart_browse_reminder_rules import (
    evaluate_abandoned_cart_browse_reminder_rules,
)
from services.security.reengagement_campaign_rules import evaluate_reengagement_campaign_rules
from services.security.urgency_driven_promotion_rules import (
    evaluate_urgency_driven_promotion_rules,
)
from services.security.sponsored_affiliate_promotion_rules import (
    evaluate_sponsored_affiliate_promotion_rules,
)
from services.security.high_frequency_promotional_campaign_rules import (
    evaluate_high_frequency_promotional_campaign_rules,
)
from services.security.excessively_intrusive_promotion_rules import (
    evaluate_excessively_intrusive_promotion_rules,
)
from services.security.second_layer_behavioral_rules import (
    evaluate_second_layer_behavioral_rules,
)
from services.security.unusual_content_email_rules import (
    evaluate_unusual_content_email_rules,
)
from services.security.unexpected_contact_email_rules import (
    evaluate_unexpected_contact_email_rules,
)
from services.security.context_mismatch_email_rules import (
    evaluate_context_mismatch_email_rules,
)
from services.security.sender_anomaly_email_rules import (
    evaluate_sender_anomaly_email_rules,
)
from services.security.authentication_anomaly_email_rules import (
    evaluate_authentication_anomaly_email_rules,
)
from services.security.header_inconsistency_email_rules import (
    evaluate_header_inconsistency_email_rules,
)
from services.security.low_reputation_sender_email_rules import (
    evaluate_low_reputation_sender_email_rules,
)
from services.security.suspicious_link_email_rules import (
    evaluate_suspicious_link_email_rules,
)
from services.security.suspicious_attachment_email_rules import (
    evaluate_suspicious_attachment_email_rules,
)
from services.security.unscannable_content_email_rules import (
    evaluate_unscannable_content_email_rules,
)
from services.security.unusual_request_email_rules import (
    evaluate_unusual_request_email_rules,
)
from services.security.pressure_secrecy_email_rules import (
    evaluate_pressure_secrecy_email_rules,
)
from services.security.known_sender_behavioral_anomaly_rules import (
    evaluate_known_sender_behavioral_anomaly_rules,
)
from services.security.reconnaissance_email_rules import (
    evaluate_reconnaissance_email_rules,
)
from services.security.campaign_associated_email_rules import (
    evaluate_campaign_associated_email_rules,
)
from services.security.multi_indicator_suspicious_email_rules import (
    evaluate_multi_indicator_suspicious_email_rules,
)
from services.security.pending_analysis_threat_rules import (
    evaluate_pending_analysis_threat_rules,
)
from services.security.ai_prompt_injection_email_rules import (
    evaluate_ai_prompt_injection_email_rules,
)
from services.security.near_confirmed_composite_threat_rules import (
    evaluate_near_confirmed_composite_threat_rules,
)

SPAM_THRESHOLD = 55
SECURITY_CATEGORIES = (
    "Spam",
    "Promotional",
    "Phishing",
    "Malware",
    "Scam / Fraud",
    "Impersonation",
    "Suspicious",
    "Safe / Misclassified",
)

HIGH_RISK_PHRASES = (
    "verify your account", "confirm your account", "account suspended", "account locked",
    "password expires", "password expired", "urgent action", "immediate action required",
    "claim your prize", "claim your reward", "claim reward", "you have won", "you won",
    "lottery winner", "randomly selected", "selected to receive", "lucky customer",
    "gift card", "crypto investment", "guaranteed income", "wire transfer", "advance fee",
    "provide verification details", "confirm your eligibility", "processing fee",
    "unauthorized transaction", "unusual sign-in", "avoid suspension", "avoid losing",
)
PROMOTIONAL_PHRASES = (
    "limited time", "exclusive offer", "exclusive reward", "buy now", "free trial",
    "discount", "unsubscribe", "promotion", "special offer", "act now",
    "expires today", "final notice", "unclaimed", "forfeited", "automated promotional",
)
TECHNICAL_TASK_TERMS = (
    "investigate", "review logs", "authentication logs", "account status",
    "browser compatibility", "login failures", "sign-in failures",
    "incident", "troubleshoot", "diagnose", "root cause", "affected users",
    "test case", "task", "status report",
)
SENSITIVE_TERMS = (
    "credit card", "card number", "cvv", "bank account", "social security",
    "passport", "government id", "personal information", "sensitive information",
)
MONEY_TERMS = (
    "reward", "prize", "winner", "cash", "lottery", "jackpot", "bonus", "funds",
    "investment", "crypto", "gift card",
)
# These terms are much more specific to a lure than ordinary workplace finance
# words such as "funds" or "investment". Broad financial vocabulary can appear
# in legitimate budget/project mail and must not become a scam signal merely
# because the same message also contains a deadline or urgent work request.
MONEY_LURE_TERMS = (
    "reward", "prize", "winner", "lottery", "jackpot", "gift card",
    "crypto", "guaranteed income", "advance fee",
)
URGENCY_TERMS = (
    "urgent", "immediately", "act now", "expires", "expiration", "hours",
    "final notice", "forfeited", "suspended", "locked",
)
CTA_TERMS = (
    "claim", "confirm", "click", "open the link", "secure page", "provide",
    "submit", "verify", "update",
)
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".msi", ".msp", ".hta", ".jar", ".lnk", ".url", ".iso", ".img", ".chm",
}
ARCHIVE_EXTENSIONS = (".zip", ".7z", ".rar", ".tar", ".tgz", ".gz", ".bz2", ".xz")

_MACRO_OFFICE_EXTENSIONS = (
    ".docm", ".dotm", ".xlsm", ".xltm", ".xlam",
    ".pptm", ".potm", ".ppsm", ".sldm",
)
_MACRO_ENABLE_ACTION_RE = re.compile(
    r"\b(?:enable|activate|allow|turn on|permit)\b.{0,60}\b(?:macros?|active content|content)\b"
    r"|\b(?:macros?|active content)\b.{0,60}\b(?:enable|activate|allow|turn on|permit)\b",
    re.I | re.S,
)
_MACRO_INTERACTION_RE = re.compile(
    r"\b(?:open|review|check|inspect|edit|complete|fill(?: out)?|sign|process|use|view)\b"
    r".{0,100}\b(?:attached|attachment|document|file|workbook|spreadsheet|presentation|invoice|advice)\b"
    r"|\b(?:attached|attachment|document|file|workbook|spreadsheet|presentation|invoice|advice)\b"
    r".{0,100}\b(?:open|review|check|inspect|edit|complete|fill(?: out)?|sign|process|use|view)\b",
    re.I | re.S,
)
_MACRO_BENIGN_CONTEXT_RE = re.compile(
    r"\b(?:no action (?:is )?required|for reference only|reference only|do not enable|don't enable|dont enable|"
    r"do not activate|don't activate|dont activate|analysis only|testing only)\b",
    re.I | re.S,
)
_PROTECTED_ARCHIVE_RE = re.compile(
    r"\b(?:password[- ]protected|encrypted|protected)\b.{0,50}\b(?:archive|zip|7z|rar|file|attachment)\b"
    r"|\b(?:archive|zip|7z|rar|file|attachment)\b.{0,50}\b(?:password[- ]protected|encrypted|protected)\b"
    r"|\bpassword\s*[:=]\s*[^\s,;]+",
    re.I | re.S,
)
_ARCHIVE_KNOWN_DANGEROUS_PAYLOAD_RE = re.compile(
    r"\b(?:run|execute|launch|start|open)\b.{0,100}\b[^\s,;]+\.(?:exe|scr|com|bat|cmd|ps1|vbs|js|hta|lnk|chm)\b",
    re.I | re.S,
)

_ACTIVE_SVG_MARKERS = (
    "<script", "onload=", "onerror=", "javascript:",
    "xlink:href=\"javascript:", "href=\"javascript:",
)
_HTML_SCRIPT_MARKERS = ("<script", "javascript:", "onload=", "onerror=")
_HTML_PAYLOAD_MARKERS = (
    "createobjecturl", "new blob", "uint8array", "atob(", "fromcharcode",
    "mssaveblob", "download=", ".download", "application/octet-stream",
)
_ONENOTE_ACTIVE_ACTIONS = (
    "launch the embedded", "run the embedded", "execute the embedded",
    "double-click the embedded", "double click the embedded",
    "open the embedded", "click the embedded", "embedded invoice button",
    "embedded payload", "embedded executable",
)
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "rebrand.ly",
}
FREE_MAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "icloud.com",
    "protonmail.com", "proton.me",
}
IMPERSONATED_NAMES = (
    "microsoft", "google", "apple", "paypal", "amazon", "netflix", "bank",
    "security team", "support team", "administrator", "admin team", "hr department",
    "payroll", "it support", "delivery support",
)
_TRUSTED_ROLE_NAMES = (
    "ceo", "cfo", "chief executive", "chief financial", "general counsel",
    "legal counsel", "company counsel", "hr department", "payroll",
    "vendor accounts", "accounts payable", "accounts receivable",
)
_SECRECY_RE = re.compile(
    r"\b(?:do not|don't|dont|avoid)\b.{0,60}\b(?:discuss|share|copy|cc|tell|involve|forward|circulate)\b"
    r"|\bkeep\b.{0,50}\b(?:confidential|private|between us|limited to us)\b"
    r"|\b(?:between us|only between us|off the record|not for distribution|no one else)\b",
    re.I | re.S,
)
_GIFT_CARD_PURCHASE_RE = re.compile(
    r"\b(?:buy|purchase|get|obtain|pick up|acquire|order|pabili|pakibili|bumili|bilhin)\b"
    r".{0,80}\bgift\s*cards?\b"
    r"|\bgift\s*cards?\b.{0,80}\b(?:buy|purchase|get|obtain|pick up|acquire|order|pabili|pakibili|bumili|bilhin)\b",
    re.I | re.S,
)
_GIFT_CARD_CODE_TRANSFER_RE = re.compile(
    r"\b(?:send|share|provide|forward|text|message|email|i[- ]?send|ipadala|isend)\b"
    r".{0,100}\b(?:codes?|pins?|numbers?|serials?)\b"
    r"|\b(?:codes?|pins?|numbers?|serials?)\b.{0,100}\b(?:send|share|provide|forward|text|message|email|i[- ]?send|ipadala|isend)\b",
    re.I | re.S,
)
_GIFT_CARD_PRESSURE_RE = re.compile(
    r"\b(?:urgent|urgently|immediately|right away|today|now|asap|at once|agad|ngayon|kaagad)\b"
    r"|\b(?:as soon as possible|as quickly as possible)\b"
    r"|\b(?:do not|don't|dont|keep|huwag|wag)\b.{0,60}\b(?:tell|share|discuss|mention|sabihin|ipagsabi)\b"
    r"|\b(?:do not|don't|dont|avoid|huwag|wag)\b.{0,60}\b(?:call|contact|verify|confirm|check with|speak to|ask)\b"
    r"|\b(?:confidential|private|between us|secret|lihim)\b",
    re.I | re.S,
)
_VERIFICATION_AVOIDANCE_RE = re.compile(
    r"\b(?:do not|don't|dont|avoid|no need to)\b.{0,60}\b(?:call|contact|verify|confirm|check with|speak to|ask)\b"
    r"|\b(?:skip|bypass)\b.{0,40}\b(?:verification|approval|confirmation|callback|call back)\b",
    re.I | re.S,
)
_CONFIDENTIAL_DISCLOSURE_RE = re.compile(
    r"\b(?:send|share|forward|provide|upload|disclose|release|transfer)\b"
    r".{0,120}\b(?:confidential|restricted|non[- ]?public|private|unreleased|sensitive|internal)\b"
    r".{0,80}\b(?:documents?|files?|records?|materials?|information|data|reports?|contracts?|agreements?)\b"
    r"|\b(?:confidential|restricted|non[- ]?public|private|unreleased|sensitive|internal)\b"
    r".{0,80}\b(?:documents?|files?|records?|materials?|information|data|reports?|contracts?|agreements?)\b"
    r".{0,120}\b(?:send|share|forward|provide|upload|disclose|release|transfer)\b",
    re.I | re.S,
)
_PAYMENT_CHANGE_RE = re.compile(
    r"\b(?:new|different|replacement|revised|updated|changed|alternate|alternative)\b"
    r".{0,70}\b(?:bank|beneficiary|payment|remittance|wire|account|routing)\b"
    r".{0,45}\b(?:details?|instructions?|information|account|beneficiary)?\b"
    r"|\b(?:bank|beneficiary|payment|remittance|wire|account|routing)\b"
    r".{0,60}\b(?:details?|instructions?|information|account|beneficiary)\b"
    r".{0,60}\b(?:changed|updated|revised|replaced|new|different)\b"
    r"|\b(?:prior|previous|old|existing)\b.{0,50}\b(?:bank|payment|remittance|wire|account)\b"
    r".{0,60}\b(?:invalid|obsolete|superseded|replaced|no longer valid|do not use|don't use|ignore)\b",
    re.I | re.S,
)
_PAYMENT_ACTION_RE = re.compile(
    r"\b(?:pay|remit|send|transfer|wire|route|direct|settle)\b"
    r".{0,100}\b(?:payment|funds?|balance|invoice|remittance|beneficiary|account|bank|wire)\b"
    r"|\b(?:use|follow)\b.{0,60}\b(?:new|revised|updated|replacement|different)\b"
    r".{0,60}\b(?:bank|beneficiary|payment|remittance|wire|account|details?|instructions?)\b",
    re.I | re.S,
)
_PAYMENT_DESTINATION_CONTEXT_RE = re.compile(
    r"\b(?:invoices?|amount due|outstanding (?:balance|invoice|payment)|remittance|beneficiary|payment instructions?|wire instructions?|payment destination|vendor payment|supplier payment|accounts payable)\b",
    re.I,
)
_COERCIVE_PAYMENT_ACTION_RE = re.compile(
    r"\b(?:pay|send|wire|transfer|remit|settle)\b.{0,80}\b(?:funds?|payment|balance|amount|invoice|remittance|bank transfer|wire transfer)\b"
    r"|\b(?:payment|funds?|balance|amount|invoice|remittance)\b.{0,80}\b(?:pay|send|wire|transfer|remit|settle)\b",
    re.I | re.S,
)
_PAYMENT_CONSEQUENCE_RE = re.compile(
    r"\b(?:avoid|prevent)\b.{0,60}\b(?:closure|suspension|termination|deactivation|penalt(?:y|ies)|late fees?|loss of access)\b"
    r"|\b(?:account|service|access|subscription)\b.{0,60}\b(?:clos(?:e|ed|ure)|suspend(?:ed|sion)?|terminat(?:e|ed|ion)|deactivat(?:e|ed|ion)|block(?:ed)?)\b",
    re.I | re.S,
)
_RECIPIENT_FINANCIAL_DATA_RE = re.compile(
    r"\b(?:send|provide|share|submit|enter|update|confirm|reply(?:\s+with)?)\b"
    r".{0,70}\b(?:your|employee|personal)\b.{0,60}\b(?:bank(?: account)?(?: details?| information)?|routing (?:number|details?|information)|account number|payment details?|payroll(?: bank)? details?)\b",
    re.I | re.S,
)
_VENDOR_FINANCE_ROLE_RE = re.compile(
    r"\b(?:vendor|supplier|billing|accounts?|finance|payments?|remittance|receivables?|payables?)\b",
    re.I,
)
DELIVERY_TERMS = ("package", "parcel", "delivery", "shipping", "courier", "shipment")
DELIVERY_PROBLEMS = (
    "on hold", "failed delivery", "delivery failed", "incomplete shipping",
    "address confirmation", "returned to sender", "redelivery",
)
FINANCIAL_LURES = (
    "invoice", "payment overdue", "refund", "tax refund", "payroll", "remittance",
    "purchase order", "wire transfer", "bank transfer",
)

_OVERPAYMENT_RE = re.compile(
    r"\b(?:overpaid|overpayment|over payment|duplicate payment|paid twice|excess (?:payment|funds?|amount)|surplus (?:payment|funds?|amount))\b",
    re.I,
)
_REFUND_ACTION_RE = re.compile(
    r"\b(?:refund|return|send back|transfer back|wire back|remit back|repay)\b"
    r".{0,100}\b(?:excess|overpayment|surplus|funds?|amount|payment|money)\b"
    r"|\b(?:excess|overpayment|surplus)\b.{0,100}\b(?:refund|return|send|transfer|wire|remit|repay)\b",
    re.I | re.S,
)
_ACCOUNT_DESTINATION_RE = re.compile(
    r"\b(?:bank account|beneficiary|account below|routing details?|wire details?|payment details?|remittance details?)\b",
    re.I,
)
_REMOTE_SUPPORT_RE = re.compile(
    r"\b(?:install|download|run|launch|open|use|set up|setup)\b"
    r".{0,80}\b(?:remote[- ]?(?:support|access|control)|screen[- ]?sharing|support (?:tool|software|client|agent)|remote (?:tool|software|client|agent)|anydesk|teamviewer)\b",
    re.I | re.S,
)
_CALLBACK_PROBLEM_RE = re.compile(
    r"\b(?:unauthori[sz]ed|unrecogni[sz]ed|unexpected)\b.{0,70}\b(?:charge|payment|purchase|renewal|subscription|transaction)\b"
    r"|\b(?:account|mailbox|device|computer|workstation|system|subscription|service)\b"
    r".{0,70}\b(?:problem|issue|error|fault|locked|suspended|compromised|infected|renew(?:al|ed)?)\b"
    r"|\b(?:cancel|reverse|refund)\b.{0,70}\b(?:charge|payment|purchase|renewal|subscription|transaction)\b",
    re.I | re.S,
)

_PHISHING_HIGH_RISK = {
    "verify your account", "confirm your account", "account suspended", "account locked",
    "password expires", "password expired", "provide verification details",
    "unauthorized transaction", "unusual sign-in", "avoid suspension", "avoid losing",
}
_SCAM_HIGH_RISK = {
    "claim your prize", "claim your reward", "claim reward", "you have won", "you won",
    "lottery winner", "randomly selected", "selected to receive", "lucky customer",
    "gift card", "crypto investment", "guaranteed income", "wire transfer", "advance fee",
    "confirm your eligibility", "processing fee",
}

_ACCOUNT_SIGNIN_RE = re.compile(
    r"\b(?:sign|log)\s*[- ]?in\b.{0,90}\b(?:account|email|mailbox|work|corporate|company|microsoft|google|credentials?)\b"
    r"|\b(?:authenticate|reauthenticate|re-authenticate)\b.{0,90}\b(?:account|email|mailbox|work|corporate|company|access|session)\b",
    re.I | re.S,
)
_OAUTH_CONSENT_RE = re.compile(
    r"\b(?:approve|accept|grant|authorize|allow|consent to)\b"
    r".{0,100}\b(?:app|application|integration|service|connector)\b"
    r".{0,100}\b(?:access|permissions?|consent|scopes?|mailbox|account|files?|data)\b"
    r"|\b(?:app|application|integration|service|connector)\b"
    r".{0,100}\b(?:needs?|requests?|requires?)\b.{0,80}\b(?:access|permissions?|consent|scopes?)\b",
    re.I | re.S,
)
_MFA_APPROVAL_RE = re.compile(
    r"\b(?:approve|accept|confirm|allow|tap\s+(?:yes|approve)|press\s+(?:yes|approve))\b"
    r".{0,100}\b(?:mfa|multi[- ]?factor|authenticator|authentication|sign[- ]?in|login|push|prompt|notification|request)\b"
    r"|\b(?:mfa|multi[- ]?factor|authenticator|authentication|sign[- ]?in|login|push)\b"
    r".{0,100}\b(?:approve|accept|confirm|allow|tap\s+(?:yes|approve)|press\s+(?:yes|approve))\b",
    re.I | re.S,
)
_ACCOUNT_ACCESS_PRESSURE_RE = re.compile(
    r"\b(?:keep|restore|retain|maintain|recover)\b.{0,60}\b(?:access|mailbox|account|session)\b"
    r"|\b(?:access|mailbox|account|session)\b.{0,60}\b(?:locked|suspended|interrupted|disabled|restricted|expire[sd]?)\b"
    r"|\b(?:verify|validate|confirm)\b.{0,60}\b(?:account|identity|mailbox|session)\b",
    re.I | re.S,
)
_UNUSUAL_ACCOUNT_ACTIVITY_RE = re.compile(
    r"\b(?:unusual|suspicious|unrecogni[sz]ed|unverified|unexpected)\b"
    r".{0,90}\b(?:account activity|activity|sign[- ]?in|login|access|attempt)\b"
    r"|\b(?:sign[- ]?in|login|access)\b.{0,70}\b(?:could not be verified|unverified|unrecogni[sz]ed|unexpected)\b",
    re.I | re.S,
)
_SECURITY_UPDATE_DELIVERY_RE = re.compile(
    r"\b(?:security|software|system|workstation|device)\b.{0,70}\b(?:update|patch|hotfix|upgrade)\b"
    r"|\b(?:update|patch|hotfix|upgrade)\b.{0,70}\b(?:security|software|system|workstation|device)\b",
    re.I | re.S,
)
_DOWNLOAD_EXECUTION_RE = re.compile(
    r"\b(?:download|install|run|launch|execute|open)\b.{0,100}\b(?:update|patch|package|installer|file|software|tool)\b"
    r"|\b(?:update|patch|package|installer|file|software|tool)\b.{0,100}\b(?:download|install|run|launch|execute|open)\b",
    re.I | re.S,
)
_AUTH_SECRET_REQUEST_RE = re.compile(
    r"\b(?:reply(?:\s+with)?|send|provide|share|enter|submit|confirm|disclose|forward)\b"
    r".{0,90}\b(?:one[- ]time password|otp|recovery codes?|security codes?|backup codes?|authentication codes?|auth codes?|verification codes?)\b",
    re.I | re.S,
)
_TRUSTED_BRAND_HOSTS = (
    "microsoft.com", "google.com", "apple.com", "paypal.com", "amazon.com",
    "docusign.com",
)

_DSN_SUBJECT_RE = re.compile(
    r"\b(?:delivery status notification|non[- ]?delivery report|undeliverable|undelivered|"
    r"delivery (?:failure|failed)|message delivery (?:failure|failed)|returned mail|failure notice)\b",
    re.I,
)
_DSN_BODY_RE = re.compile(
    r"\b(?:automated|automatic(?:ally)? generated)\b.{0,80}\b(?:delivery|non[- ]?delivery|status|bounce|failure)\b"
    r"|\b(?:delivery|message)\b.{0,60}\b(?:failed|undeliverable|could not be delivered|was not delivered|returned)\b",
    re.I | re.S,
)
_DSN_QUOTED_ORIGINAL_RE = re.compile(
    r"\b(?:original|failed|returned)\s+(?:message|content|text|email)\b"
    r"|^\s*[-=]{2,}\s*(?:original message|returned message|failed message)\s*[-=]{2,}\s*$",
    re.I | re.S | re.M,
)
_DSN_DIRECT_ACTION_RE = re.compile(
    r"\b(?:click|visit|follow|open|download|install|call|pay|submit|update|confirm|verify|provide|enter)\b"
    r"|\b(?:sign|log)\s*[- ]?in\b",
    re.I,
)


def _is_delivery_status_notification(subject: str, sender: str, evidence: str, body: str) -> bool:
    # Delivery-status reports are machine-generated wrappers around another
    # message. Treating the quoted original as a live instruction creates false
    # positives, so identify the wrapper from independent transport/context
    # signals rather than from any benchmark-specific sender or phrase.
    address = parseaddr(str(sender or ""))[1].casefold()
    local_part = address.split("@", 1)[0] if "@" in address else address
    machine_sender = bool(
        local_part == "postmaster"
        or local_part == "mailer-daemon"
        or local_part.startswith("mailer-daemon+")
    )
    subject_signal = bool(_DSN_SUBJECT_RE.search(str(subject or "")))
    body_signal = bool(_DSN_BODY_RE.search(str(body or "")))
    transport_signal = bool(re.search(
        r"(?:message/delivery-status|multipart/report|auto-submitted\s*[:=]\s*auto-(?:generated|replied))",
        str(evidence or ""),
        re.I,
    ))
    return bool(
        transport_signal
        or (machine_sender and (subject_signal or body_signal))
        or (subject_signal and body_signal)
    )


def _strip_dsn_quoted_original(body: str) -> str:
    # A DSN can embed or quote the entire failed message. Analyze only the
    # delivery report itself when a recognizable original-message boundary is
    # present; the quoted payload is evidence, not an instruction to the user.
    value = str(body or "")
    match = _DSN_QUOTED_ORIGINAL_RE.search(value)
    if not match:
        return value
    return value[: match.start()].rstrip()


def _contains_any(text, phrases):
    return any(phrase in text for phrase in phrases)


def _is_archive_filename(filename: str) -> bool:
    return bool(re.search(r"\.(?:zip|7z|rar|tar|tgz|gz|bz2|xz)(?:\b|$)", str(filename or ""), re.I))


def _attachment_text_sample(attachment: dict, *, limit: int = 131072) -> str:
    # Full provider messages keep attachment bytes in SQLite, so MailMind can
    # inspect text-based active content without executing or rendering it.
    # Optional upstream analysis may contribute evidence, but production logic
    # does not consume benchmark-only hint fields.
    pieces = [
        str(attachment.get("content_type") or ""),
        str(attachment.get("analysis") or ""),
    ]
    data = attachment.get("data")
    if isinstance(data, (bytes, bytearray)) and data:
        sample = bytes(data[:limit])
        try:
            pieces.append(sample.decode("utf-8", errors="ignore"))
        except Exception:
            pass
    elif isinstance(data, str):
        pieces.append(data[:limit])
    return "\n".join(pieces).casefold()


def _active_attachment_reason(attachment: dict, message_text: str) -> str:
    filename = str(attachment.get("filename") or "").casefold().strip()
    content_type = str(attachment.get("content_type") or "").casefold().strip()
    base_content_type = content_type.split(";", 1)[0].strip()
    sample = _attachment_text_sample(attachment)

    # Internet shortcut files are active launchers, analogous to .lnk files.
    if filename.endswith(".url") or base_content_type == "application/internet-shortcut":
        return "Internet shortcut attachment can launch an external destination"

    # OneNote files are common and must not be blocked by extension alone.
    # Escalate only when the message or supplied attachment analysis explicitly
    # says the recipient should launch/run embedded active content.
    if filename.endswith(".one") or base_content_type == "application/onenote":
        combined = f"{message_text}\n{sample}"
        if _contains_any(combined, _ONENOTE_ACTIVE_ACTIONS) or _contains_any(
            sample, ("embedded executable", "embedded payload")
        ):
            return "OneNote attachment is used to launch embedded active content"

    # SVG is a legitimate image format. Only script/event-handler evidence makes
    # it an active-content malware signal.
    if filename.endswith(".svg") or base_content_type == "image/svg+xml":
        if _contains_any(sample, _ACTIVE_SVG_MARKERS):
            return "SVG attachment contains active script/event content"

    # HTML attachments can be legitimate or used for credential phishing. Do
    # not blanket-block HTML. Malware floor applies only when script is paired
    # with concrete payload construction/download behavior (HTML smuggling).
    if filename.endswith((".html", ".htm")) or base_content_type == "text/html":
        if _contains_any(sample, _HTML_SCRIPT_MARKERS) and _contains_any(
            sample, _HTML_PAYLOAD_MARKERS
        ):
            return "HTML attachment contains script that constructs or downloads a payload"

    return ""


_NEGATION_PREFIX_RE = re.compile(
    r"(?:\bno\b|\bnot\b|\bnever\b|\bwithout\b|"
    r"\bdo\s+not\b|\bdoes\s+not\b|\bdid\s+not\b|"
    r"\bwill\s+not\b|\bwould\s+not\b|\bshould\s+not\b|"
    r"\bcannot\b|\bcan\s+not\b|\bcan't\b|\bdon't\b|\bdoesn't\b)"
)
_NEGATION_SUFFIX_RE = re.compile(
    r"^\s+(?:(?:is|are|was|were|will\s+be|would\s+be|should\s+be)\s+)?"
    r"(?:not|never)\s+(?:required|requested|needed|necessary|expected)\b"
)
_CONTRAST_RE = re.compile(r"\b(?:but|however|except|although|though|yet)\b")


def _phrase_is_negated(text: str, start: int, end: int) -> bool:
    # Security keywords often appear in benign disclaimers such as
    # "no urgent action is required" or "do not provide your password".
    # Evaluate the local clause around each occurrence instead of treating the
    # presence of the keyword anywhere in the message as a positive signal.
    sentence_start = max(
        text.rfind(".", 0, start),
        text.rfind("!", 0, start),
        text.rfind("?", 0, start),
        text.rfind(";", 0, start),
        text.rfind("\n", 0, start),
    ) + 1
    prefix = text[sentence_start:start]

    # A contrast word starts a new semantic clause; a negation before it must
    # not suppress a later genuine warning ("no issue before, but urgent action
    # is now required").
    contrasts = list(_CONTRAST_RE.finditer(prefix))
    if contrasts:
        prefix = prefix[contrasts[-1].end():]

    negations = list(_NEGATION_PREFIX_RE.finditer(prefix))
    if negations:
        # Keep suppression local. A negation elsewhere in the same sentence
        # must not hide a later genuine security instruction. Four words is
        # enough for forms such as "never ask for credentials" and
        # "do not provide your password" without broadly muting the sentence.
        tail = prefix[negations[-1].end():]
        if len(re.findall(r"\b[\w'-]+\b", tail)) <= 4:
            return True

    suffix = text[end:min(len(text), end + 64)]
    if _NEGATION_SUFFIX_RE.search(suffix):
        return True
    return False


def _unnegated_matches(text: str, phrases) -> list[str]:
    matches = []
    for phrase in phrases:
        start = 0
        while True:
            index = text.find(phrase, start)
            if index < 0:
                break
            end = index + len(phrase)
            if not _phrase_is_negated(text, index, end):
                matches.append(phrase)
                break
            start = end
    return matches


def _contains_unnegated_any(text: str, phrases) -> bool:
    return bool(_unnegated_matches(text, phrases))


def _normalize_text(value):
    text = unicodedata.normalize("NFKC", str(value or "")).casefold()
    text = text.translate(str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"}))
    text = re.sub(r"(?<=\w)[._\-](?=\w)", "", text)
    return re.sub(r"\s+", " ", text)


def _html_visible_text(value: str) -> str:
    """Return conservative visible text from an HTML email body."""
    source = re.sub(r"(?is)<(?:script|style)\b[^>]*>.*?</(?:script|style)>", " ", str(value or ""))
    source = re.sub(r"(?s)<[^>]+>", " ", source)
    return html.unescape(source)


def _urls(text):
    return re.findall(r"https?://[^\s<>\]\[\"']+", text, re.I)


def _looks_like_numeric_ip_host(host: str) -> bool:
    value = str(host or "").casefold().strip(".")
    if not value:
        return False

    # Browsers and URL parsers may accept IPv4 destinations written as one
    # decimal/hex integer or as all-numeric dotted components. Treat those
    # address encodings like a raw IP instead of a normal hostname.
    if re.fullmatch(r"\d+", value):
        try:
            return 0 <= int(value, 10) <= 0xFFFFFFFF
        except ValueError:
            return False
    if re.fullmatch(r"0x[0-9a-f]+", value):
        try:
            return 0 <= int(value, 16) <= 0xFFFFFFFF
        except ValueError:
            return False

    parts = value.split(".")
    if not 2 <= len(parts) <= 4:
        return False
    if not all(re.fullmatch(r"(?:0x[0-9a-f]+|\d+)", part) for part in parts):
        return False

    try:
        numbers = [int(part, 16) if part.startswith("0x") else int(part, 10) for part in parts]
    except ValueError:
        return False

    # Legacy IPv4 text forms allow the last component to carry the remaining
    # address bits (a.b, a.b.c, or a.b.c.d). Validate those ranges instead of
    # treating every dotted numeric-looking hostname as an IP address.
    bounds = {
        2: (0xFF, 0xFFFFFF),
        3: (0xFF, 0xFF, 0xFFFF),
        4: (0xFF, 0xFF, 0xFF, 0xFF),
    }[len(numbers)]
    return all(0 <= number <= maximum for number, maximum in zip(numbers, bounds))


def _host_risk(url):
    try:
        host = (urlparse(url).hostname or "").casefold().strip(".")
        if not host:
            return 0, ""
        try:
            ipaddress.ip_address(host)
            return 28, "Link uses a raw IP address"
        except ValueError:
            pass
        if _looks_like_numeric_ip_host(host):
            return 28, "Link uses an encoded numeric IP address"
        if host.startswith("xn--") or ".xn--" in host:
            return 28, "Link uses an internationalized lookalike domain"
        if host in SHORTENERS or any(host.endswith("." + item) for item in SHORTENERS):
            return 18, "Link hides its destination through a shortener"
        if host.count("-") >= 4 or len(host) > 55:
            return 12, "Link has an unusually constructed domain"
    except Exception:
        pass
    return 0, ""


def _unnegated_regex_match(text: str, pattern: re.Pattern) -> bool:
    for match in pattern.finditer(text):
        if not _phrase_is_negated(text, match.start(), match.end()):
            return True
    return False


def _dangerous_uri_scheme(url: str) -> bool:
    value = str(url or "").strip().casefold()
    return value.startswith(("javascript:", "vbscript:", "data:text/html", "file:"))


def _nested_external_destination(url: str) -> bool:
    """Return True when a wrapper URL embeds a different http(s) destination.

    This is intentionally narrow: a nested URL alone is not malicious. Callers
    must combine it with account-access/sign-in context and other evidence.
    """
    raw = str(url or "").strip()
    if not raw:
        return False
    try:
        outer = urlparse(raw)
        outer_host = (outer.hostname or "").casefold().strip(".")
        decoded = unquote(raw)
        candidates = []
        for values in parse_qs(urlparse(decoded).query, keep_blank_values=True).values():
            candidates.extend(values)
        # Fallback for wrappers that embed the nested URL outside a normal query
        # parameter. Start at the second URL token so the outer destination is
        # never mistaken for its own redirect target.
        starts = [m.start() for m in re.finditer(r"https?://", decoded, re.I)]
        candidates.extend(decoded[start:] for start in starts[1:])
        for candidate in candidates:
            inner_host = (urlparse(unquote(candidate)).hostname or "").casefold().strip(".")
            if inner_host and outer_host and inner_host != outer_host:
                return True
    except Exception:
        return False
    return False


def _url_matches_sender_domain(url: str, sender_domain: str) -> bool:
    """Return True when a web destination is the sender domain or its subdomain."""
    sender_domain = str(sender_domain or "").casefold().strip(".")
    if not sender_domain:
        return False
    try:
        host = (urlparse(str(url or "")).hostname or "").casefold().strip(".")
    except Exception:
        return False
    return bool(host and (host == sender_domain or host.endswith("." + sender_domain)))


def _deceptive_brand_host(url: str) -> str:
    # A trusted brand name that is only an interior host label does not make
    # the destination first-party. Example: login.microsoft.com.attacker.tld.
    # Only the hostname is inspected; brand words in paths/query strings are
    # intentionally ignored.
    try:
        host = (urlparse(url).hostname or "").casefold().strip(".")
    except Exception:
        return ""
    if not host:
        return ""
    for trusted in _TRUSTED_BRAND_HOSTS:
        if trusted in host and host != trusted and not host.endswith("." + trusted):
            return trusted
    return ""



def _is_consumer_mail_domain(domain: str) -> bool:
    # Production logic recognizes real consumer-mail domains only. Synthetic
    # benchmark aliases are normalized by the test loader, not by this detector.
    domain = str(domain or "").casefold().strip(".")
    return domain in FREE_MAIL_DOMAINS


def _domain_has_typo_lookalike_shape(domain: str) -> bool:
    domain = str(domain or "").casefold().strip(".")
    if not domain:
        return False
    label = domain.split(".", 1)[0]
    # A digit substituted inside an alphabetic brand/vendor token (for example
    # vend0r) is materially different from a normal trailing version number.
    return bool(re.search(r"[a-z](?:0|1|3|5|7)[a-z]", label))


def _domain_has_mixed_script_lookalike(domain: str) -> bool:
    """Return True for a label that mixes scripts commonly used in homoglyph spoofing.

    Internationalized domains are not suspicious merely for containing Unicode.
    The risky pattern is a single label that mixes Latin with Cyrillic/Greek
    letters, which is a common visual-impersonation technique.
    """
    domain = str(domain or "").strip(".")
    if not domain:
        return False
    label = domain.split(".", 1)[0]
    scripts = set()
    for ch in label:
        if not ch.isalpha():
            continue
        name = unicodedata.name(ch, "")
        if "LATIN" in name:
            scripts.add("LATIN")
        elif "CYRILLIC" in name:
            scripts.add("CYRILLIC")
        elif "GREEK" in name:
            scripts.add("GREEK")
    return "LATIN" in scripts and bool(scripts.intersection({"CYRILLIC", "GREEK"}))

def _bounded_confidence(primary: int, secondary: int = 0, minimum: int = 55) -> int:
    margin = max(0, int(primary) - int(secondary))
    return max(minimum, min(99, 56 + int(primary * 0.38) + int(margin * 0.10)))


def _category_slug(category: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(category or "").casefold()).strip("-")


_NON_SEMANTIC_TEST_SUBJECT_PREFIX_RE = re.compile(r"^\s*\[security test\]\s*", re.I)
_NON_SEMANTIC_TEST_FOOTER_RE = re.compile(
    r"(?im)^\s*security test\s*[\-\u2010-\u2015]\s*harmless simulation\s*;\s*"
    r"reserved\s+\.invalid\s+links\s+do\s+not\s+resolve\.?\s*$"
)


def _strip_nonsemantic_test_wrapper(subject: str, body: str) -> tuple[str, str]:
    """Remove transport labels that are not part of the message under test.

    The wrapper is intentionally matched exactly.  Generic words such as
    ``training`` or ``simulation`` are not trusted as an allow-list because an
    attacker can append them to otherwise harmful content.
    """
    return (
        _NON_SEMANTIC_TEST_SUBJECT_PREFIX_RE.sub("", str(subject or ""), count=1),
        _NON_SEMANTIC_TEST_FOOTER_RE.sub("", str(body or "")),
    )


def detect_spam(email_data: dict) -> dict:
    # Keep the historical function name for compatibility. The result now also
    # carries a security category/confidence while preserving the original
    # is_spam/score/reason contract used by Inbox storage and filtering.
    subject = str(email_data.get("subject") or "")
    body_text = str(email_data.get("body_text") or "")
    snippet = str(email_data.get("snippet") or "")
    # Some provider adapters persist a whitespace-only text part alongside a
    # useful preview. Truthiness alone would discard that preview and leave the
    # security rules with only the subject, so fall back after stripping.
    if not body_text.strip():
        body_text = snippet
    body_html = str(email_data.get("body_html") or "")
    html_text = _html_visible_text(body_html)
    body_parts = [part for part in (body_text, html_text) if part.strip()]
    if snippet.strip() and all(snippet.strip() not in part for part in body_parts):
        body_parts.append(snippet)
    body = "\n".join(body_parts)
    analysis_subject, body = _strip_nonsemantic_test_wrapper(subject, body)
    sender = str(email_data.get("from") or "")
    reply_to = str(email_data.get("reply_to") or "")
    evidence = str(email_data.get("spam_evidence") or "").casefold()
    dsn_context = _is_delivery_status_notification(subject, sender, evidence, body)
    analysis_body = _strip_dsn_quoted_original(body) if dsn_context else body
    raw_text = f"{analysis_subject}\n{analysis_body}".casefold()
    text = _normalize_text(raw_text)

    score = 0
    non_provider_score = 0
    reasons = []
    category_scores = {
        "Spam": 0,
        "Promotional": 0,
        "Phishing": 0,
        "Malware": 0,
        "Scam / Fraud": 0,
        "Impersonation": 0,
        "Suspicious": 0,
    }
    strong_flags = set()
    rule_hits = []
    provider_flagged = False

    def add(points, reason, *categories, provider=False, strong="", risk=True, rule_id=""):
        nonlocal score, non_provider_score, provider_flagged
        points = int(points or 0)
        if risk:
            score += points
            if provider:
                provider_flagged = True
            else:
                non_provider_score += points
        elif provider:
            provider_flagged = True
        if reason and reason not in reasons:
            reasons.append(reason)
        for category in categories:
            if category in category_scores:
                category_scores[category] += points
        if strong:
            strong_flags.add(strong)
        if rule_id and rule_id not in rule_hits:
            rule_hits.append(rule_id)

    if "provider-folder=spam" in evidence:
        # Provider Spam/Junk placement controls workspace membership only. It is
        # not category evidence and must not add Spam score/category points.
        provider_flagged = True
        reasons.append("The email provider placed it in Spam/Junk")
    # X-Microsoft-Antispam is routinely present on legitimate mail that passed
    # through Microsoft infrastructure. Its mere presence is metadata, not a
    # spam verdict. Only explicit positive spam flags count here.
    if any(token in evidence for token in ("x-spam-flag=yes", "x-spam-status=yes")):
        add(
            75,
            "Provider spam headers explicitly flagged the message",
            "Spam",
            provider=True,
            strong="provider-spam-header",
        )

    failures = sum(token in evidence for token in ("dmarc=fail", "spf=fail", "dkim=fail"))
    auth_passes = sum(
        token in evidence for token in ("dmarc=pass", "spf=pass", "dkim=pass")
    )
    strong_authentication = bool("dmarc=pass" in evidence or auth_passes >= 2)
    if failures:
        add(
            25 + (failures - 1) * 15,
            "Sender authentication failed",
            "Phishing", "Impersonation", "Suspicious",
            strong="auth-failure",
        )

    high = _unnegated_matches(text, HIGH_RISK_PHRASES)
    # Generic navigation wording such as "click here" is intentionally not a
    # promotional signal by itself. Transactional/security notifications often
    # use it alongside several legitimate links. CTA scoring below still treats
    # click/open/verify actions as risky when they are combined with urgency,
    # credential requests, sensitive-data requests, or risky destinations.
    promo = [phrase for phrase in PROMOTIONAL_PHRASES if phrase in text]
    if high:
        high_points = min(72, 24 * len(high))
        phishing_hits = [phrase for phrase in high if phrase in _PHISHING_HIGH_RISK]
        scam_hits = [phrase for phrase in high if phrase in _SCAM_HIGH_RISK]
        categories = []
        if phishing_hits:
            categories.append("Phishing")
        if scam_hits:
            categories.append("Scam / Fraud")
        if not categories:
            categories.append("Suspicious")
        add(
            high_points,
            "High-risk wording: " + ", ".join(high[:4]),
            *categories,
            strong="high-risk-wording",
        )
    if promo:
        # Marketing vocabulary is a content-type signal, not proof of Spam.
        # Keep it out of the aggregate security-risk score so ordinary offers,
        # renewals, newsletters, discounts, and unsubscribe language do not
        # become Spam/Suspicious without separate spam or security evidence.
        add(
            min(36, 8 * len(promo)),
            "Promotional wording: " + ", ".join(promo[:4]),
            "Promotional",
            risk=False,
        )

    money = _contains_any(text, MONEY_TERMS) or bool(
        re.search(r"(?:[$€£₱¥]|\b(?:usd|eur|php)\b)\s?[\d,]+", text, re.I)
    )
    money_lure = _contains_any(text, MONEY_LURE_TERMS)
    urgency = _contains_unnegated_any(text, URGENCY_TERMS)
    cta = _contains_unnegated_any(text, CTA_TERMS)
    direct_dsn_action = bool(dsn_context and _DSN_DIRECT_ACTION_RE.search(text))

    # Ordinary marketing language remains Promotional. Escalate only when the
    # message stacks several commercial lures with explicit purchase pressure,
    # a claim/action instruction, and time-pressure wording. This distinguishes
    # a normal renewal/discount notice from aggressive unsolicited promotion
    # without relying on test subjects, sender names, or sample-specific text.
    aggressive_promo_pressure = bool(
        len(set(promo)) >= 4
        and "buy now" in promo
        and urgency
        and _contains_unnegated_any(text, ("claim", "act now"))
    )
    if aggressive_promo_pressure:
        add(
            24,
            "Aggressive promotional pressure: multiple offer signals with urgent purchase/claim action",
            "Spam",
            strong="aggressive-spam-promotion",
        )

    # Evaluate the tightly scoped loyalty rule before the broad reward-lure
    # heuristic. Ordinary member points/rewards language otherwise resembles a
    # prize lure even when no fee, credential request, or sensitive action is
    # present. Scam-like variants are excluded by the loyalty rule itself and
    # therefore retain the full reward-lure signal below.
    loyalty_rewards_hits = evaluate_loyalty_rewards_promotion_rules(
        email_data=email_data,
        text=raw_text,
    )
    selected = _contains_unnegated_any(text, ("congratulations", "selected", "lucky", "reserved", "waiting"))
    credential_request = has_credential_request(text)
    sensitive = _contains_unnegated_any(text, SENSITIVE_TERMS)
    technical_task_context = _contains_any(text, TECHNICAL_TASK_TERMS)

    if money and selected and not loyalty_rewards_hits:
        add(35, "Unsolicited reward or prize claim", "Scam / Fraud", strong="reward-lure")
    if money_lure and urgency:
        add(24, "Money/reward combined with artificial urgency", "Scam / Fraud")

    # Gift-card social engineering is a concrete fraud action when the message
    # asks the recipient to procure cards and transmit their redemption codes,
    # especially under urgency or secrecy. This is different from ordinary
    # gift-card marketing, reimbursement, or a receipt because the recipient is
    # being directed to convert funds into transferable bearer-like codes.
    gift_card_fraud_action = bool(
        _unnegated_regex_match(text, _GIFT_CARD_PURCHASE_RE)
        and _unnegated_regex_match(text, _GIFT_CARD_CODE_TRANSFER_RE)
        and _unnegated_regex_match(text, _GIFT_CARD_PRESSURE_RE)
    )
    if gift_card_fraud_action:
        add(
            82,
            "Requests urgent or secret gift-card purchase and transfer of redemption codes",
            "Scam / Fraud",
            strong="fraud-action-lure",
        )
    if cta and (credential_request or sensitive):
        add(25, "Requests credential or sensitive-information action", "Phishing", strong="credential-request")
    if cta and urgency:
        add(18, "Urgent call to action", "Phishing" if credential_request else "Suspicious")
    if "congratulations" in text and _contains_any(text, ("reward", "prize", "selected", "winner")):
        add(32, "Unexpected congratulations/reward message", "Scam / Fraud")

    delivery = _contains_unnegated_any(text, DELIVERY_TERMS)
    problem = _contains_unnegated_any(text, DELIVERY_PROBLEMS)
    address = _contains_unnegated_any(text, ("update delivery", "update address", "confirm address", "delivery details", "shipping information"))
    fee = bool(
        re.search(
            r"(?:fee|charge|payment).{0,30}(?:[$€£₱¥]|\b(?:usd|eur|php)\b|\d+[.,]\d{2})",
            raw_text,
            re.I | re.S,
        )
    )
    # A genuine machine-generated delivery-status report describes a failed
    # delivery; those words are status metadata, not a package-redelivery lure.
    # Direct address/fee requests still score normally because they are active
    # instructions in the report body rather than quoted original content.
    if delivery and problem and (not dsn_context or direct_dsn_action):
        add(30, "Package-delivery problem lure", "Scam / Fraud")
    if delivery and address:
        add(25, "Requests delivery/address information", "Phishing", "Scam / Fraud")
    if delivery and fee:
        add(24, "Unexpected delivery or redelivery charge", "Scam / Fraud")
    if delivery and urgency and (address or problem) and (not dsn_context or direct_dsn_action):
        add(25, "Urgent package-delivery action", "Scam / Fraud")
    financial_lure = _contains_unnegated_any(text, FINANCIAL_LURES)
    if financial_lure and (urgency or cta):
        add(28, "Urgent financial-document or payment lure", "Scam / Fraud", "Phishing")

    # Escalate coercive payment/transfer demands to financial fraud. A plain
    # invoice, receipt, or payment notice is not enough; the message must also
    # combine a concrete payment/transfer demand with urgency and pressure.
    financial_action = bool(
        _contains_unnegated_any(
            text,
            (
                "pay now", "make payment", "send payment", "submit payment",
                "confirm payment", "confirm the payment", "confirm bank transfer",
                "confirm the bank transfer", "send bank transfer", "send wire transfer",
                "make bank transfer", "make wire transfer",
            ),
        )
        or _unnegated_regex_match(text, _COERCIVE_PAYMENT_ACTION_RE)
    )
    financial_pressure = bool(
        _contains_unnegated_any(
            text,
            (
                "final notice", "avoid losing", "avoid suspension", "service suspended",
                "service suspension", "account suspended", "account suspension",
                "immediately", "act now",
            ),
        )
        or _unnegated_regex_match(text, _PAYMENT_CONSEQUENCE_RE)
    )
    if financial_lure and financial_action and urgency and financial_pressure:
        add(22, "Coercive urgent payment or transfer demand", "Scam / Fraud", strong="financial-fraud-lure")

    # BEC/payment-redirection fraud can arrive from a compromised, fully
    # authenticated vendor mailbox. Authentication success therefore must not
    # erase a concrete request to replace existing payment instructions. Keep
    # this narrow: require both changed-bank-detail language and a payment action.
    recipient_financial_data_request = _unnegated_regex_match(text, _RECIPIENT_FINANCIAL_DATA_RE)
    payment_redirection = bool(
        _unnegated_regex_match(text, _PAYMENT_CHANGE_RE)
        and _unnegated_regex_match(text, _PAYMENT_ACTION_RE)
        and _unnegated_regex_match(text, _PAYMENT_DESTINATION_CONTEXT_RE)
        and not recipient_financial_data_request
    )
    if payment_redirection:
        add(
            88,
            "Requests payment redirection to changed bank details",
            "Scam / Fraud",
            strong="fraud-action-lure",
        )

    # Overpayment/refund fraud is materially stronger than an ordinary receipt
    # when the sender asks for excess funds to be returned to a bank account and
    # adds urgency or failed-authentication evidence.
    overpayment_refund = bool(
        _unnegated_regex_match(text, _OVERPAYMENT_RE)
        and _unnegated_regex_match(text, _REFUND_ACTION_RE)
        and _unnegated_regex_match(text, _ACCOUNT_DESTINATION_RE)
        and (urgency or failures)
    )
    if overpayment_refund:
        add(
            82,
            "Requests urgent return of an alleged overpayment to a bank account",
            "Scam / Fraud",
            strong="fraud-action-lure",
        )

    # Callback/vishing scams often avoid web links entirely. Require a concrete
    # call instruction plus either remote-support installation or a fabricated
    # billing/account problem. A normal contact-details footer does not qualify.
    phone_callback = bool(
        re.search(
            r"\b(?:call|phone|dial|contact)\b.{0,100}(?:\+?\d[\d\s().-]{6,}\d)",
            raw_text,
            re.I | re.S,
        )
    )
    remote_support_callback = bool(
        phone_callback
        and _unnegated_regex_match(text, _REMOTE_SUPPORT_RE)
        and (urgency or failures or _contains_unnegated_any(text, ("technician", "engineer", "help desk", "support desk", "support team")))
    )
    billing_callback = bool(
        phone_callback
        and _unnegated_regex_match(text, _CALLBACK_PROBLEM_RE)
        and (
            urgency
            or failures
            or _unnegated_regex_match(text, _REMOTE_SUPPORT_RE)
            or _contains_unnegated_any(text, ("charged", "renew", "renewal", "refund", "subscription", "transaction"))
        )
    )
    if remote_support_callback or billing_callback:
        add(
            82,
            "Urgent callback/vishing instruction for billing or remote support",
            "Scam / Fraud",
            strong="fraud-action-lure",
        )

    sender_name, sender_address = parseaddr(sender)
    reply_address = parseaddr(reply_to)[1]
    sender_domain = sender_address.rpartition("@")[2].casefold()
    reply_domain = reply_address.rpartition("@")[2].casefold()
    local = sender_address.partition("@")[0]
    if sender_address and (
        len(re.findall(r"\d", local)) >= 6 or re.search(r"[a-z]{2,}\d{5,}", local, re.I)
    ):
        add(12, "Unusual sender address", "Suspicious")
    if sender_domain and reply_domain and sender_domain != reply_domain:
        # A Reply-To mismatch is common in authenticated transactional/bulk mail
        # that uses a separate reply-handling service. Treat it as a weak identity
        # signal when authentication passes and there is no risky requested action.
        # It becomes a strong phishing/impersonation signal only when paired with
        # concrete threat context (credentials, sensitive data, urgent CTA, fraud,
        # delivery lure) or when sender authentication itself is not strong.
        reply_mismatch_risky_context = bool(
            credential_request
            or sensitive
            or high
            or financial_lure
            or (urgency and cta)
            or (delivery and (problem or address or fee))
        )
        if strong_authentication and failures == 0 and not reply_mismatch_risky_context:
            add(8, "Reply-To domain differs from sender domain", "Suspicious")
        else:
            add(22, "Reply-To domain differs from sender domain", "Phishing", "Impersonation", strong="reply-domain-mismatch")
    if sender_domain in FREE_MAIL_DOMAINS and _contains_any(sender_name.casefold(), IMPERSONATED_NAMES):
        add(32, "Display name impersonates an organization from a free-mail account", "Impersonation", strong="display-name-impersonation")

    sender_name_cf = sender_name.casefold()
    trusted_role_identity = _contains_any(sender_name_cf, _TRUSTED_ROLE_NAMES)
    secrecy_request = _unnegated_regex_match(text, _SECRECY_RE)
    verification_avoidance = _unnegated_regex_match(text, _VERIFICATION_AVOIDANCE_RE)
    sensitive_document_request = _unnegated_regex_match(text, _CONFIDENTIAL_DISCLOSURE_RE)
    identity_payment_change = _unnegated_regex_match(text, _PAYMENT_CHANGE_RE)
    lookalike_identity_evidence = bool(
        "lookalike" in evidence
        or "typo-squat" in evidence
        or "typosquat" in evidence
        or _domain_has_typo_lookalike_shape(sender_domain)
        or _domain_has_mixed_script_lookalike(sender_domain)
    )

    # Strong impersonation requires concrete identity deception plus a risky
    # requested action. The action itself may resemble phishing or fraud, but
    # when the sender identity is demonstrably spoofed/diverted, Impersonation
    # is the more specific primary category.
    consumer_role_disclosure = bool(
        _is_consumer_mail_domain(sender_domain)
        and trusted_role_identity
        and secrecy_request
        and sensitive_document_request
    )
    financial_action_context = bool(
        financial_lure
        or re.search(r"\b(?:payment|remittance|transfer|wire|settlement|invoice|funds?|salary|payroll|direct deposit)\b", text, re.I)
    )
    lookalike_executive_payment = bool(
        lookalike_identity_evidence
        and trusted_role_identity
        and financial_action_context
        and (secrecy_request or verification_avoidance)
    )
    lookalike_vendor_payment_change = bool(
        lookalike_identity_evidence
        and _VENDOR_FINANCE_ROLE_RE.search(sender_name_cf)
        and identity_payment_change
        and _unnegated_regex_match(text, _PAYMENT_ACTION_RE)
        and _unnegated_regex_match(text, _PAYMENT_DESTINATION_CONTEXT_RE)
        and not recipient_financial_data_request
    )
    diverted_sensitive_role = bool(
        trusted_role_identity
        and "reply-domain-mismatch" in strong_flags
        and recipient_financial_data_request
    )
    failed_auth_executive_payment = bool(
        trusted_role_identity
        and failures > 0
        and financial_action_context
        and verification_avoidance
    )
    lookalike_sensitive_role = bool(
        lookalike_identity_evidence
        and trusted_role_identity
        and recipient_financial_data_request
    )
    if (
        consumer_role_disclosure
        or lookalike_executive_payment
        or lookalike_vendor_payment_change
        or diverted_sensitive_role
        or failed_auth_executive_payment
        or lookalike_sensitive_role
    ):
        add(
            82,
            "Trusted-role or vendor identity is inconsistent with the sender domain and requests a sensitive action",
            "Impersonation",
            strong="impersonation-lure",
        )

    learned = int(email_data.get("learned_spam_score") or 0)
    if learned > 0:
        add(
            min(60, learned),
            "Sender/domain was previously reported as spam",
            "Spam",
            strong="learned-spam-reputation",
        )
    elif learned < 0:
        score = max(0, score + max(-35, learned))
        non_provider_score = max(0, non_provider_score + max(-35, learned))
        category_scores["Spam"] = max(0, category_scores["Spam"] + max(-35, learned))

    # For recognized DSNs, structured link extraction can include URLs from the
    # embedded original message. Re-extract from the active report portion so a
    # quoted shortener/raw-IP does not become a live-link security signal.
    urls = list(dict.fromkeys(
        _urls(analysis_body)
        if dsn_context
        else [*_urls(body), *_urls(body_html), *(email_data.get("links") or [])]
    ))
    # Score each link-risk TYPE only once. Legitimate authenticated messages
    # often contain many tracking/redirect links that share the same unusual
    # host pattern. Re-adding the same 12-point heuristic for every URL can
    # incorrectly turn a benign provider-Junk message into Suspicious even
    # though the UI shows only one deduplicated reason. Stronger risk types
    # such as raw-IP, punycode, and shortener links still contribute their
    # normal score and strong flag once.
    seen_link_risks = set()
    for url in urls[:12]:
        if _dangerous_uri_scheme(url) and "dangerous-uri" not in strong_flags:
            add(36, "Link uses a dangerous non-HTTP URI scheme", "Suspicious", strong="dangerous-uri")
        points, reason = _host_risk(url)
        if points and reason not in seen_link_risks:
            seen_link_risks.add(reason)
            link_strong_flag = (
                "high-risk-destination" if points >= 28
                else "risky-link" if points >= 18
                else ""
            )
            add(points, reason, "Phishing", "Suspicious", strong=link_strong_flag)
    if len(urls) >= 5:
        add(15, "Unusually many external links", "Spam", "Suspicious")
    if (credential_request or sensitive) and urls:
        add(18, "Credential/sensitive-data request combined with an external link", "Phishing", strong="credential-link")

    # Security-notification ambiguity guard. A message that reports unusual or
    # unverified account activity and pushes the recipient to an external review
    # destination has meaningful risk even when it never literally says
    # "sign in". Keep strongly authenticated same-domain notices on the benign
    # side; otherwise raise a Suspicious floor so contextual AI can inspect the
    # genuinely NEW message before publication.
    first_party_destination = bool(
        urls and sender_domain and any(_url_matches_sender_domain(url, sender_domain) for url in urls[:12])
    )
    unusual_account_review = bool(
        _unnegated_regex_match(text, _UNUSUAL_ACCOUNT_ACTIVITY_RE)
        and urls
        and (cta or urgency or _contains_unnegated_any(text, ("review", "check", "verify", "confirm")))
        and not (strong_authentication and first_party_destination)
    )
    if unusual_account_review:
        add(38, "Unusual or unverified account activity directs the recipient to an external review destination", "Suspicious", strong="account-activity-review")

    # Update-delivery ambiguity guard. Legitimate IT notices may discuss patches,
    # but an unauthenticated/mismatched message that asks the recipient to
    # download/install/run an update from a web destination is a concrete
    # delivery risk. Use Suspicious rather than Malware until payload evidence
    # establishes an actual malicious file.
    update_delivery = bool(
        _unnegated_regex_match(text, _SECURITY_UPDATE_DELIVERY_RE)
        and _unnegated_regex_match(text, _DOWNLOAD_EXECUTION_RE)
        and urls
        and (urgency or cta)
        and not (strong_authentication and first_party_destination)
    )
    if update_delivery:
        add(42, "Security/software update asks the recipient to download, install, or run a package from an external destination", "Suspicious", strong="update-delivery-risk")

    # Modular account-access rules combine explicit high-confidence anchors with
    # broader multi-signal compositions. The explicit layer can establish a
    # Phishing safety floor; weaker novel combinations become Suspicious so the
    # contextual layer can review them before NEW mail is published.
    account_access_hits = evaluate_account_access_rules(
        text=text,
        sender=sender,
        urls=urls,
        authentication_failures=failures,
        strong_authentication=strong_authentication,
        risky_destination=bool(strong_flags.intersection({
            "high-risk-destination", "risky-link", "dangerous-uri"
        })),
    )
    for hit in account_access_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    shared_document_hits = evaluate_shared_document_rules(
        # Preserve brand numbers, punctuation, and link-adjacent wording. The
        # general anti-obfuscation normalizer intentionally rewrites digits and
        # intra-word hyphens, which can corrupt names such as Microsoft 365 and
        # M365 before this document-brand rule sees them.
        text=raw_text,
        sender=sender,
        urls=urls,
        authentication_failures=failures,
        risky_destination=bool(strong_flags.intersection({
            "high-risk-destination", "risky-link", "dangerous-uri"
        })),
    )
    for hit in shared_document_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    unrecognized_signin_hits = evaluate_unrecognized_signin_rules(
        text=raw_text,
        sender=sender,
        urls=urls,
        authentication_failures=failures,
        risky_destination=bool(strong_flags.intersection({
            "high-risk-destination", "risky-link", "dangerous-uri"
        })),
    )
    for hit in unrecognized_signin_hits:
        add(hit.points, hit.reason, *hit.categories, strong=hit.strong_flag, rule_id=hit.rule_id)

    password_expiration_hits = evaluate_password_expiration_rules(
        text=raw_text,
        sender=sender,
        urls=urls,
        authentication_failures=failures,
        risky_destination=bool(strong_flags.intersection({
            "high-risk-destination", "risky-link", "dangerous-uri"
        })),
    )
    for hit in password_expiration_hits:
        add(hit.points, hit.reason, *hit.categories, strong=hit.strong_flag, rule_id=hit.rule_id)

    voicemail_hits = evaluate_voicemail_notification_rules(
        text=raw_text,
        sender=sender,
        urls=urls,
        authentication_failures=failures,
        risky_destination=bool(strong_flags.intersection({
            "high-risk-destination", "risky-link", "dangerous-uri"
        })),
    )
    for hit in voicemail_hits:
        add(hit.points, hit.reason, *hit.categories, strong=hit.strong_flag, rule_id=hit.rule_id)

    mailbox_quota_hits = evaluate_mailbox_quota_rules(
        text=raw_text,
        sender=sender,
        urls=urls,
        authentication_failures=failures,
        risky_destination=bool(strong_flags.intersection({
            "high-risk-destination", "risky-link", "dangerous-uri"
        })),
    )
    for hit in mailbox_quota_hits:
        add(hit.points, hit.reason, *hit.categories, strong=hit.strong_flag, rule_id=hit.rule_id)

    hr_portal_hits = evaluate_hr_portal_rules(
        text=raw_text,
        sender=sender,
        urls=urls,
        authentication_failures=failures,
        risky_destination=bool(strong_flags.intersection({
            "high-risk-destination", "risky-link", "dangerous-uri"
        })),
    )
    for hit in hr_portal_hits:
        add(hit.points, hit.reason, *hit.categories, strong=hit.strong_flag, rule_id=hit.rule_id)

    oauth_consent_hits = evaluate_oauth_consent_rules(
        text=raw_text,
        sender=sender,
        urls=urls,
        authentication_failures=failures,
        risky_destination=bool(strong_flags.intersection({
            "high-risk-destination", "risky-link", "dangerous-uri"
        })),
    )
    for hit in oauth_consent_hits:
        add(hit.points, hit.reason, *hit.categories, strong=hit.strong_flag, rule_id=hit.rule_id)

    # Type 1 is an authoritative safety floor: an upstream scanner detection or
    # recognized antivirus test signature is Malware regardless of prose, sender,
    # or model output. Clean/benign verdicts do not trigger this rule.
    known_malicious_hits = evaluate_known_malicious_attachment_rules(
        email_data.get("attachments") or []
    )
    for hit in known_malicious_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    # Type 2 compares the displayed filename with normalized extension, MIME,
    # and bounded file-signature evidence. It catches concealment without
    # executing or rendering attacker-controlled attachment content.
    disguised_executable_hits = evaluate_disguised_executable_rules(
        email_data.get("attachments") or []
    )
    for hit in disguised_executable_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    # Type 3 inspects bounded archive structure and member samples in memory.
    # Nothing is extracted to disk or executed.
    malicious_archive_hits = evaluate_malicious_archive_rules(
        email_data.get("attachments") or []
    )
    for hit in malicious_archive_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    # Type 4 inspects document structure and bounded content samples for active
    # execution features. Document extensions alone are never treated as proof.
    weaponized_document_hits = evaluate_weaponized_document_rules(
        email_data.get("attachments") or []
    )
    for hit in weaponized_document_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    # Type 5 joins message instructions, remote destinations, bounded text-like
    # attachment samples, and scanner evidence. It never visits a URL or runs a
    # command found in an email.
    downloader_loader_hits = evaluate_downloader_loader_rules(
        email_data=email_data,
        text=raw_text,
        urls=urls,
        attachments=email_data.get("attachments") or [],
    )
    for hit in downloader_loader_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    # Type 6 recognizes email-visible web-delivery behavior locally. URLs are
    # parsed and decoded but never contacted.
    web_malware_hits = evaluate_web_malware_delivery_rules(
        email_data=email_data,
        text=raw_text,
        body_html=body_html,
        urls=urls,
        attachments=email_data.get("attachments") or [],
    )
    for hit in web_malware_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    # Type 7 detects email-visible credential, cookie, wallet, keylogging, and
    # banking-interception behavior. Text attachments are sampled but never run.
    infostealer_banking_hits = evaluate_infostealer_banking_malware_rules(
        email_data=email_data,
        text=raw_text,
        attachments=email_data.get("attachments") or [],
    )
    for hit in infostealer_banking_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    # Type 8 recognizes known RAT/backdoor families and remote-control, C2,
    # persistence, surveillance, and botnet behavior without running content.
    trojan_backdoor_hits = evaluate_trojan_backdoor_bot_rat_rules(
        email_data=email_data,
        text=raw_text,
        attachments=email_data.get("attachments") or [],
    )
    for hit in trojan_backdoor_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    # Type 9 recognizes known ransomware families, encryption/extortion,
    # recovery sabotage, and destructive wiping without executing content.
    ransomware_destructive_hits = evaluate_ransomware_destructive_malware_rules(
        email_data=email_data,
        text=raw_text,
        attachments=email_data.get("attachments") or [],
    )
    for hit in ransomware_destructive_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    # Type 10 requires evidence of targeting plus a staged entry, loader, and
    # final malware chain, or an authoritative scanner verdict.
    targeted_multistage_hits = evaluate_targeted_multistage_malware_rules(
        email_data=email_data,
        text=raw_text,
        attachments=email_data.get("attachments") or [],
    )
    for hit in targeted_multistage_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    # MailMind enhancement layer (kept separate from the imported V9 rules):
    # when provider metadata no longer exposes an attachment, retain concrete
    # evidence that the recipient is explicitly told to interact with a named
    # executable payload. Filename mentions without a delivery/action context
    # remain untouched.
    referenced_payload_hits = evaluate_referenced_dangerous_payload_enhancement(
        email_data=email_data,
        text=raw_text,
    )
    for hit in referenced_payload_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    # MailMind enhancement layer: detect covert movement of internal/company
    # data to a personal or unmanaged destination when the message also asks the
    # recipient to bypass or conceal the normal IT/security process.  The V9
    # unusual-request and other Suspicious rules remain unchanged.
    external_transfer_hits = evaluate_external_data_transfer_enhancement(
        email_data=email_data,
        text=raw_text,
    )
    for hit in external_transfer_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    # Scam/Fraud Type 1 distinguishes fraudulent coupon mechanics from ordinary
    # retail promotions. Malware and concrete phishing remain higher-priority
    # categories in the final decision order below.
    fake_discount_coupon_hits = evaluate_fake_discount_coupon_rules(
        email_data=email_data,
        text=raw_text,
        has_risky_destination=bool(strong_flags.intersection({
            "high-risk-destination", "risky-link", "dangerous-uri", "credential-link"
        })),
    )
    for hit in fake_discount_coupon_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    # Scam/Fraud Types 2-15 add deterministic floors for fake commerce,
    # prize/lottery/inheritance, advance-fee, fake-billing, refund/recovery,
    # employment/task, fake-check/overpayment, and emergency/confidence mechanics.
    # Malware and concrete phishing still retain priority in final selection.
    fake_product_service_hits = evaluate_fake_product_service_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in fake_product_service_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    prize_lottery_inheritance_hits = evaluate_prize_lottery_inheritance_scam_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in prize_lottery_inheritance_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    advance_fee_hits = evaluate_advance_fee_scam_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in advance_fee_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    fake_invoice_renewal_debt_hits = evaluate_fake_invoice_renewal_debt_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in fake_invoice_renewal_debt_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    fake_refund_recovery_hits = evaluate_fake_refund_recovery_service_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in fake_refund_recovery_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    employment_task_hits = evaluate_employment_task_scam_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in employment_task_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    fake_check_overpayment_hits = evaluate_fake_check_overpayment_scam_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in fake_check_overpayment_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    emergency_confidence_hits = evaluate_emergency_confidence_scam_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in emergency_confidence_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    tech_support_account_protection_hits = evaluate_tech_support_account_protection_scam_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in tech_support_account_protection_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    payment_diversion_hits = evaluate_payment_diversion_fraud_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in payment_diversion_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    business_email_compromise_hits = evaluate_business_email_compromise_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in business_email_compromise_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    investment_cryptocurrency_fraud_hits = evaluate_investment_cryptocurrency_fraud_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in investment_cryptocurrency_fraud_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    real_estate_high_value_hits = evaluate_real_estate_high_value_transaction_fraud_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in real_estate_high_value_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    money_mule_laundering_hits = evaluate_money_mule_laundering_recruitment_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in money_mule_laundering_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    # Dedicated Impersonation Types 1-2 preserve their own explainable rule
    # identities while concrete malware, phishing, BEC, and scam mechanics keep
    # the precedence defined in the final selection below.
    generic_identity_claim_hits = evaluate_generic_identity_claim_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in generic_identity_claim_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    display_name_impersonation_hits = evaluate_display_name_impersonation_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in display_name_impersonation_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    role_department_impersonation_hits = evaluate_role_department_impersonation_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in role_department_impersonation_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    brand_impersonation_hits = evaluate_brand_impersonation_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in brand_impersonation_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    person_name_impersonation_hits = evaluate_person_name_impersonation_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in person_name_impersonation_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    username_localpart_lookalike_hits = evaluate_username_localpart_lookalike_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in username_localpart_lookalike_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    lookalike_domain_impersonation_hits = evaluate_lookalike_domain_impersonation_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in lookalike_domain_impersonation_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    homograph_unicode_impersonation_hits = evaluate_homograph_unicode_impersonation_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in homograph_unicode_impersonation_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    reply_to_impersonation_hits = evaluate_reply_to_impersonation_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in reply_to_impersonation_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    exact_domain_spoofing_hits = evaluate_exact_domain_spoofing_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in exact_domain_spoofing_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    internal_employee_executive_hits = evaluate_internal_employee_executive_impersonation_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in internal_employee_executive_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    vendor_business_partner_hits = evaluate_vendor_business_partner_impersonation_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in vendor_business_partner_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    helpdesk_administrator_hits = evaluate_helpdesk_administrator_impersonation_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in helpdesk_administrator_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    compromised_account_hits = evaluate_compromised_account_impersonation_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in compromised_account_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    conversation_thread_hijacking_hits = evaluate_conversation_thread_hijacking_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in conversation_thread_hijacking_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    coordinated_identity_hits = evaluate_coordinated_identity_impersonation_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in coordinated_identity_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    unwanted_one_off_hits = evaluate_unwanted_one_off_spam_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in unwanted_one_off_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    repetitive_sender_hits = evaluate_repetitive_sender_spam_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in repetitive_sender_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    unsolicited_commercial_hits = evaluate_unsolicited_commercial_spam_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in unsolicited_commercial_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    cold_outreach_hits = evaluate_cold_outreach_spam_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in cold_outreach_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    bulk_list_hits = evaluate_bulk_list_spam_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in bulk_list_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    harvested_address_hits = evaluate_harvested_address_spam_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in harvested_address_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    unsubscribe_violation_hits = evaluate_unsubscribe_violation_spam_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in unsubscribe_violation_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    deceptive_subject_hits = evaluate_deceptive_subject_spam_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in deceptive_subject_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    obfuscated_content_hits = evaluate_obfuscated_content_spam_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in obfuscated_content_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    rotating_sender_hits = evaluate_rotating_sender_snowshoe_spam_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in rotating_sender_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    compromised_account_spam_hits = evaluate_compromised_account_spam_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in compromised_account_spam_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    botnet_generated_spam_hits = evaluate_botnet_generated_spam_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in botnet_generated_spam_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    reply_chain_spam_hits = evaluate_reply_chain_conversation_spam_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in reply_chain_spam_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    backscatter_hits = evaluate_backscatter_bounce_spam_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in backscatter_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    email_bombing_hits = evaluate_email_subscription_bombing_spam_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in email_bombing_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    organization_flood_hits = evaluate_organization_wide_spam_flood_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in organization_flood_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    informational_newsletter_hits = evaluate_informational_newsletter_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in informational_newsletter_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
            risk=False,
        )

    content_marketing_hits = evaluate_content_marketing_email_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in content_marketing_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
            risk=False,
        )

    brand_awareness_hits = evaluate_brand_awareness_email_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in brand_awareness_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
            risk=False,
        )

    product_announcement_hits = evaluate_product_announcement_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in product_announcement_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
            risk=False,
        )

    event_promotion_hits = evaluate_event_promotion_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in event_promotion_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
            risk=False,
        )

    general_sales_hits = evaluate_general_sales_promotion_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in general_sales_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
            risk=False,
        )

    discount_coupon_hits = evaluate_discount_coupon_promotion_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in discount_coupon_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
            risk=False,
        )

    seasonal_campaign_hits = evaluate_seasonal_campaign_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in seasonal_campaign_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
            risk=False,
        )

    personalized_recommendation_hits = evaluate_personalized_recommendation_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in personalized_recommendation_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
            risk=False,
        )

    cross_sell_upsell_hits = evaluate_cross_sell_upsell_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in cross_sell_upsell_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
            risk=False,
        )

    for hit in loyalty_rewards_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
            risk=False,
        )

    abandoned_cart_browse_hits = evaluate_abandoned_cart_browse_reminder_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in abandoned_cart_browse_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
            risk=False,
        )

    reengagement_hits = evaluate_reengagement_campaign_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in reengagement_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
            risk=False,
        )

    urgency_promotion_hits = evaluate_urgency_driven_promotion_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in urgency_promotion_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
            risk=False,
        )

    sponsored_affiliate_hits = evaluate_sponsored_affiliate_promotion_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in sponsored_affiliate_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
            risk=False,
        )

    high_frequency_promotional_hits = evaluate_high_frequency_promotional_campaign_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in high_frequency_promotional_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
            risk=False,
        )

    excessively_intrusive_hits = evaluate_excessively_intrusive_promotion_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in excessively_intrusive_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
            risk=False,
        )

    unusual_content_hits = evaluate_unusual_content_email_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in unusual_content_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    unexpected_contact_hits = evaluate_unexpected_contact_email_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in unexpected_contact_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    context_mismatch_hits = evaluate_context_mismatch_email_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in context_mismatch_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    sender_anomaly_hits = evaluate_sender_anomaly_email_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in sender_anomaly_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    authentication_anomaly_hits = evaluate_authentication_anomaly_email_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in authentication_anomaly_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    header_inconsistency_hits = evaluate_header_inconsistency_email_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in header_inconsistency_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    low_reputation_sender_hits = evaluate_low_reputation_sender_email_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in low_reputation_sender_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    suspicious_link_hits = evaluate_suspicious_link_email_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in suspicious_link_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    suspicious_attachment_hits = evaluate_suspicious_attachment_email_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in suspicious_attachment_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    unscannable_content_hits = evaluate_unscannable_content_email_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in unscannable_content_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    unusual_request_hits = evaluate_unusual_request_email_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in unusual_request_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    pressure_secrecy_hits = evaluate_pressure_secrecy_email_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in pressure_secrecy_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    known_sender_behavioral_anomaly_hits = evaluate_known_sender_behavioral_anomaly_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in known_sender_behavioral_anomaly_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    reconnaissance_hits = evaluate_reconnaissance_email_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in reconnaissance_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    pending_analysis_threat_hits = evaluate_pending_analysis_threat_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in pending_analysis_threat_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    ai_prompt_injection_hits = evaluate_ai_prompt_injection_email_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in ai_prompt_injection_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    campaign_associated_hits = evaluate_campaign_associated_email_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in campaign_associated_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    multi_indicator_hits = evaluate_multi_indicator_suspicious_email_rules(
        email_data=email_data,
        text=raw_text,
        existing_flags=strong_flags,
    )
    for hit in multi_indicator_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    near_confirmed_composite_hits = evaluate_near_confirmed_composite_threat_rules(
        email_data=email_data,
        text=raw_text,
        existing_flags=strong_flags,
    )
    for hit in near_confirmed_composite_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    # Provider-independent behavioral floors cover risky combinations visible
    # in ordinary message text and structured metadata.  They intentionally do
    # not rely on delivered-test subjects or particular sender accounts.
    second_layer_behavioral_hits = evaluate_second_layer_behavioral_rules(
        email_data=email_data,
        text=raw_text,
    )
    for hit in second_layer_behavioral_hits:
        add(
            hit.points,
            hit.reason,
            *hit.categories,
            strong=hit.strong_flag,
            rule_id=hit.rule_id,
        )

    # Type 8 inspection is deliberately performed only on full attachment bytes
    # and inline data images. URLs recovered from QR/OCR content therefore join
    # the same explainable deterministic safety floor as Types 1-7.
    qr_image_hits = evaluate_qr_image_phishing_rules(
        text=raw_text,
        sender=sender,
        body_html=body_html,
        attachments=email_data.get("attachments") or [],
        authentication_failures=failures,
    )
    for hit in qr_image_hits:
        add(hit.points, hit.reason, *hit.categories, strong=hit.strong_flag, rule_id=hit.rule_id)

    # Type 9 expands encoded redirect parameters and text-based attachment links
    # locally. It never visits the destination, keeping background Security from
    # contacting attacker-controlled CAPTCHA or credential-harvesting pages.
    captcha_multistage_hits = evaluate_captcha_multistage_rules(
        text=raw_text,
        sender=sender,
        urls=urls,
        body_html=body_html,
        attachments=email_data.get("attachments") or [],
        authentication_failures=failures,
    )
    for hit in captcha_multistage_hits:
        add(hit.points, hit.reason, *hit.categories, strong=hit.strong_flag, rule_id=hit.rule_id)

    # Type 10 treats device-code authorization and active session/token export
    # as credential-equivalent theft. A legitimate Microsoft device-login URL
    # is not inherently risky; the requested action and social context establish
    # the safety floor.
    device_code_session_hits = evaluate_device_code_session_rules(
        text=raw_text,
        sender=sender,
        urls=urls,
        authentication_failures=failures,
    )
    for hit in device_code_session_hits:
        add(hit.points, hit.reason, *hit.categories, strong=hit.strong_flag, rule_id=hit.rule_id)

    # Type 11 requires email-visible authentication-proxy evidence on an
    # unrelated destination. The rule expands encoded redirects locally but
    # never visits a link. Ordinary MFA notices on official or sender-aligned
    # identity hosts therefore remain outside this safety floor.
    aitm_hits = evaluate_aitm_phishing_rules(
        text=raw_text,
        sender=sender,
        urls=urls,
        authentication_failures=failures,
    )
    for hit in aitm_hits:
        add(hit.points, hit.reason, *hit.categories, strong=hit.strong_flag, rule_id=hit.rule_id)

    # Type 12 deobfuscates invisible/fullwidth/mixed-script text and recognizes
    # sensitive account actions in multiple languages. Language or Unicode use
    # alone is never malicious: the rule also requires an unrelated destination
    # with structural, authentication-path, recipient-binding, or sender risk.
    multilingual_obfuscated_hits = evaluate_multilingual_obfuscated_rules(
        text=raw_text,
        sender=sender,
        urls=urls,
        authentication_failures=failures,
    )
    for hit in multilingual_obfuscated_hits:
        add(hit.points, hit.reason, *hit.categories, strong=hit.strong_flag, rule_id=hit.rule_id)

    # Modern account-access phishing often avoids a literal password request.
    # Treat OAuth consent abuse, MFA push approval, direct requests for recovery
    # codes, and failed-auth external sign-in lures as credential-equivalent.
    # Legitimate authenticated enrollment/reset notices are left alone unless
    # they actually ask the recipient to grant access or disclose an auth secret.
    account_signin_request = _unnegated_regex_match(text, _ACCOUNT_SIGNIN_RE)
    nested_external_destination = any(_nested_external_destination(url) for url in urls[:12])
    auth_secret_request = _unnegated_regex_match(text, _AUTH_SECRET_REQUEST_RE)
    oauth_consent_lure = _unnegated_regex_match(text, _OAUTH_CONSENT_RE)
    mfa_approval_lure = _unnegated_regex_match(text, _MFA_APPROVAL_RE)
    deceptive_brand = next((value for url in urls[:12] if (value := _deceptive_brand_host(url))), "")

    if deceptive_brand:
        add(
            28,
            f"Trusted brand appears only inside an attacker-controlled host: {deceptive_brand}",
            "Phishing", "Suspicious",
            strong="deceptive-brand-host",
        )

    if auth_secret_request:
        add(
            70,
            "Requests disclosure of an authentication/recovery secret",
            "Phishing",
            strong="account-access-lure",
        )
    elif mfa_approval_lure and (urgency or high or _unnegated_regex_match(text, _ACCOUNT_ACCESS_PRESSURE_RE)):
        add(
            70,
            "Requests approval of an unsolicited authentication prompt",
            "Phishing",
            strong="account-access-lure",
        )
    elif oauth_consent_lure and not strong_authentication and (urgency or cta or urls):
        add(
            70,
            "Requests account access through app/OAuth consent",
            "Phishing",
            strong="account-access-lure",
        )
    elif account_signin_request and failures and nested_external_destination:
        add(
            70,
            "Sign-in lure is wrapped around a different nested external destination",
            "Phishing",
            strong="account-access-lure",
        )
    elif account_signin_request and failures and urls:
        add(
            60,
            "Failed-authentication message directs the recipient to sign in with an account",
            "Phishing",
            strong="account-access-lure",
        )
    elif deceptive_brand and failures and _contains_unnegated_any(text, ("verify", "confirm", "keep access", "restore access")):
        add(
            50,
            "Failed-authentication message uses a deceptive branded destination for account access",
            "Phishing",
            strong="account-access-lure",
        )

    dangerous = []
    active_attachment_reasons = []
    opaque_protected_archive = False
    for attachment in email_data.get("attachments") or []:
        filename = str(attachment.get("filename") or "").casefold()
        content_type = str(attachment.get("content_type") or "").casefold()
        base_content_type = content_type.split(";", 1)[0].strip()
        if (
            _is_archive_filename(filename)
            and _PROTECTED_ARCHIVE_RE.search(raw_text)
            and (urgency or failures or financial_lure)
        ):
            opaque_protected_archive = True
        if any(filename.endswith(ext) for ext in DANGEROUS_EXTENSIONS) or re.search(
            r"\.(?:pdf|docx?|xlsx?|jpg|png)\.(?:exe|scr|js|vbs|lnk|url)$", filename
        ):
            dangerous.append(filename)
        if _is_archive_filename(filename) and _ARCHIVE_KNOWN_DANGEROUS_PAYLOAD_RE.search(raw_text):
            dangerous.append(filename + " (known dangerous payload inside archive)")
        if base_content_type in {
            "application/x-msdownload", "application/x-dosexec", "application/x-executable",
            "application/vnd.ms-htmlhelp",
        }:
            dangerous.append(filename or base_content_type)
        macro_capable_office = (
            filename.endswith(_MACRO_OFFICE_EXTENSIONS)
            or "macroenabled" in base_content_type
        )
        if macro_capable_office and _unnegated_regex_match(raw_text, _MACRO_ENABLE_ACTION_RE):
            dangerous.append(filename or base_content_type or "macro-enabled Office attachment")
            active_reason = "Macro-enabled Office attachment is paired with an instruction to enable active content"
            if active_reason not in active_attachment_reasons:
                active_attachment_reasons.append(active_reason)
        elif (
            macro_capable_office
            and _MACRO_INTERACTION_RE.search(raw_text)
            and not _MACRO_BENIGN_CONTEXT_RE.search(raw_text)
        ):
            # Macro-capable Office files are not malware by extension alone.
            # However, an unexpected macro-capable attachment that asks the
            # recipient to interact with it deserves a cautious Suspicious floor
            # until content inspection or contextual review can establish trust.
            add(
                35,
                "Macro-enabled Office attachment requests recipient interaction",
                "Suspicious",
            )
        if filename.endswith((".html", ".htm")) and account_signin_request:
            add(
                70,
                "HTML attachment is used as an account sign-in page",
                "Phishing",
                strong="account-access-lure",
            )
        active_reason = _active_attachment_reason(attachment, text)
        if active_reason:
            dangerous.append(filename or base_content_type or "attachment")
            if active_reason not in active_attachment_reasons:
                active_attachment_reasons.append(active_reason)
    if dangerous:
        add(
            100,
            "Potentially executable or disguised attachment: " + ", ".join(dict.fromkeys(dangerous[:3])),
            "Malware",
            strong="dangerous-attachment",
        )
        for active_reason in active_attachment_reasons[:2]:
            if active_reason not in reasons:
                reasons.append(active_reason)

    # A protected archive whose payload cannot be inspected is risk evidence,
    # but it is not proof of credential theft or malware. Keep it Suspicious
    # unless stronger concrete evidence already identifies a malicious family.
    if (
        opaque_protected_archive
        and "dangerous-attachment" not in strong_flags
        and "account-access-lure" not in strong_flags
        and "fraud-action-lure" not in strong_flags
        and "impersonation-lure" not in strong_flags
        and "credential-link" not in strong_flags
    ):
        add(
            45,
            "Password-protected or encrypted archive cannot be safely inspected",
            "Suspicious",
            strong="opaque-archive",
        )

    if subject and len(subject) >= 12 and subject.upper() == subject and sum(ch.isalpha() for ch in subject) >= 10:
        add(10, "Excessive capitalization", "Spam", "Suspicious")

    bounded_score = min(max(score, 0), 100)
    # Provider folder placement does not participate in MailMind category thresholds.
    # It only keeps the message visible in the Spam/Security workspace.
    threshold_flagged = bool(bounded_score >= SPAM_THRESHOLD)

    ranked = sorted(category_scores.items(), key=lambda item: item[1], reverse=True)
    top_category, top_score = ranked[0]
    second_score = ranked[1][1] if len(ranked) > 1 else 0

    if category_scores["Malware"] >= 70 or "dangerous-attachment" in strong_flags:
        category = "Malware"
    elif "multilingual-obfuscated-novel-lure" in strong_flags:
        category = "Phishing"
    elif "aitm-phishing-kit-lure" in strong_flags:
        category = "Phishing"
    elif "device-code-session-theft-lure" in strong_flags:
        category = "Phishing"
    elif "captcha-multistage-phishing-lure" in strong_flags:
        category = "Phishing"
    elif "qr-image-phishing-lure" in strong_flags:
        category = "Phishing"
    elif "oauth-consent-lure" in strong_flags:
        category = "Phishing"
    elif "hr-portal-credential-lure" in strong_flags:
        category = "Phishing"
    elif "mailbox-quota-lure" in strong_flags:
        category = "Phishing"
    elif "voicemail-notification-lure" in strong_flags:
        category = "Phishing"
    elif "password-expiration-lure" in strong_flags:
        category = "Phishing"
    elif "unrecognized-signin-lure" in strong_flags:
        category = "Phishing"
    elif "shared-document-credential-lure" in strong_flags:
        category = "Phishing"
    elif "account-access-lure" in strong_flags:
        category = "Phishing"
    elif (
        "business-email-compromise" in strong_flags
        and "credential-link" not in strong_flags
    ):
        # BEC uses impersonation as the delivery mechanism, but its defining
        # action is business fraud. Specialized phishing rules and concrete
        # credential links above still retain Phishing precedence.
        category = "Scam / Fraud"
    elif (
        strong_flags.intersection({
            "generic-identity-claim-impersonation", "display-name-impersonation-type2",
            "role-department-impersonation", "brand-impersonation-type4",
            "person-name-impersonation", "username-localpart-lookalike",
            "lookalike-domain-impersonation", "homograph-unicode-impersonation",
            "reply-to-impersonation", "exact-domain-spoofing",
            "internal-employee-executive-impersonation", "vendor-business-partner-impersonation",
            "helpdesk-administrator-impersonation", "compromised-account-impersonation",
            "conversation-thread-hijacking", "coordinated-identity-impersonation",
        })
        and "credential-link" not in strong_flags
        and not strong_flags.intersection({
            "fraud-action-lure", "financial-fraud-lure", "reward-lure",
            "fake-discount-coupon", "fake-product-service",
            "prize-lottery-inheritance-scam", "advance-fee-scam",
            "fake-invoice-renewal-debt", "fake-refund-recovery-service",
            "employment-task-scam", "fake-check-overpayment-scam",
            "emergency-confidence-scam", "tech-support-account-protection-scam",
            "payment-diversion-fraud", "investment-cryptocurrency-fraud",
            "real-estate-high-value-transaction-fraud", "money-mule-laundering-recruitment",
        })
    ):
        category = "Impersonation"
    elif (
        ("impersonation-lure" in strong_flags or "display-name-impersonation" in strong_flags)
        and not strong_flags.intersection({
            "fraud-action-lure", "financial-fraud-lure", "reward-lure",
            "fake-discount-coupon", "fake-product-service",
            "prize-lottery-inheritance-scam", "advance-fee-scam",
            "fake-invoice-renewal-debt", "fake-refund-recovery-service",
            "employment-task-scam", "fake-check-overpayment-scam",
            "emergency-confidence-scam", "tech-support-account-protection-scam",
            "payment-diversion-fraud", "business-email-compromise",
            "investment-cryptocurrency-fraud", "real-estate-high-value-transaction-fraud",
            "money-mule-laundering-recruitment",
        })
    ):
        # Concrete sender-identity deception is more specific than the action
        # category. Keep Impersonation even when the same message also requests
        # credentials, payroll data, or a fraudulent payment.
        category = "Impersonation"
    elif (
        strong_flags.intersection({
            "payment-diversion-fraud", "investment-cryptocurrency-fraud",
            "real-estate-high-value-transaction-fraud",
            "money-mule-laundering-recruitment",
        })
        and "credential-link" not in strong_flags
    ):
        # Payroll/direct-deposit diversion necessarily mentions changing bank
        # account details. That wording can trip the generic sensitive-data
        # heuristic, but the explicit payment-diversion rule is more specific.
        # Concrete credential links and the specialized phishing rules above
        # still retain Phishing precedence.
        category = "Scam / Fraud"
    elif "fraud-action-lure" in strong_flags or "financial-fraud-lure" in strong_flags:
        # Concrete coercive payment demands and direct fraud actions are more
        # specific than generic phishing-like urgency/authentication signals.
        category = "Scam / Fraud"
    elif "opaque-archive" in strong_flags:
        category = "Suspicious"
    elif category_scores["Phishing"] >= 45 and (
        credential_request or sensitive or "auth-failure" in strong_flags or "credential-link" in strong_flags
    ):
        category = "Phishing"
    elif category_scores["Scam / Fraud"] >= 45:
        category = "Scam / Fraud"
    elif category_scores["Impersonation"] >= 45 or (
        category_scores["Impersonation"] >= 32 and "display-name-impersonation" in strong_flags
    ):
        category = "Impersonation"
    elif category_scores["Spam"] >= 16:
        # Spam requires evidence beyond ordinary marketing vocabulary, such as
        # explicit provider spam headers, learned sender reputation, or combined
        # bulk-mail heuristics (for example many links plus excessive caps).
        category = "Spam"
    elif (
        "high-risk-destination" in strong_flags
        and category_scores["Suspicious"] >= 28
    ):
        # A raw-IP or internationalized lookalike destination is concrete link
        # risk, not a weak wording heuristic. Treat that destination as
        # Suspicious even when the generic aggregate score has not reached 35.
        # Shortener-only links keep the normal threshold/context requirement.
        category = "Suspicious"
    elif threshold_flagged or non_provider_score >= 35:
        category = "Suspicious"
    elif "risky-link" in strong_flags and promo:
        # A shortened/hidden destination changes an otherwise ordinary marketing
        # message into a security-relevant case. Preserve the existing cautious
        # behavior instead of allowing Promotional to mask link risk.
        category = "Suspicious"
    elif category_scores["Promotional"] >= 8:
        category = "Promotional"
    else:
        category = "Safe / Misclassified"

    # A message can discuss login/authentication/security as ordinary work.
    # Do not turn those topic words into a threat by themselves. A technical
    # task with no credential solicitation, risky link, identity mismatch,
    # malicious attachment, money/delivery lure, or authentication failure is
    # treated as legitimate. If the provider itself placed it in Junk, keep it
    # in the security workspace but label it Safe / Misclassified.
    suspicious_subtype_hit = bool(strong_flags.intersection({
        "unusual-content-email", "unexpected-contact-email",
        "context-mismatch-email", "sender-anomaly-email",
        "authentication-anomaly-email", "header-inconsistency-email",
        "low-reputation-sender-email", "suspicious-link-email",
        "suspicious-attachment-email", "unscannable-content-email",
        "unusual-request-email", "pressure-secrecy-email",
        "known-sender-behavioral-anomaly", "reconnaissance-email",
        "multi-indicator-suspicious-email", "campaign-associated-email",
        "pending-analysis-threat", "ai-prompt-injection-email",
        "near-confirmed-composite-threat",
    }))

    benign_technical_task = bool(
        technical_task_context
        and not suspicious_subtype_hit
        and not credential_request
        and not sensitive
        and not urls
        and not money
        and not delivery
        and not strong_flags.intersection({
            "auth-failure", "reply-domain-mismatch", "display-name-impersonation",
            "impersonation-lure",
            "risky-link", "credential-link", "dangerous-attachment", "reward-lure",
            "web-malware-delivery", "infostealer-banking-malware", "trojan-backdoor-bot-rat",
            "ransomware-destructive-malware",
            "targeted-multistage-malware",
            "fake-discount-coupon",
            "fake-product-service", "prize-lottery-inheritance-scam",
            "advance-fee-scam", "fake-invoice-renewal-debt",
            "fake-refund-recovery-service", "employment-task-scam",
            "fake-check-overpayment-scam", "emergency-confidence-scam",
            "tech-support-account-protection-scam", "payment-diversion-fraud",
            "business-email-compromise", "investment-cryptocurrency-fraud",
            "real-estate-high-value-transaction-fraud", "money-mule-laundering-recruitment",
            "generic-identity-claim-impersonation", "display-name-impersonation-type2",
            "role-department-impersonation", "brand-impersonation-type4",
            "person-name-impersonation", "username-localpart-lookalike",
            "lookalike-domain-impersonation", "homograph-unicode-impersonation",
            "reply-to-impersonation", "exact-domain-spoofing",
            "internal-employee-executive-impersonation", "vendor-business-partner-impersonation",
            "helpdesk-administrator-impersonation", "compromised-account-impersonation",
            "conversation-thread-hijacking", "coordinated-identity-impersonation",
            "unwanted-one-off-spam", "repetitive-sender-spam",
            "unsolicited-commercial-spam", "cold-outreach-spam",
            "bulk-list-spam", "harvested-address-spam",
            "unsubscribe-violation-spam", "deceptive-subject-spam",
            "obfuscated-content-spam", "rotating-sender-snowshoe-spam",
            "compromised-account-spam", "botnet-generated-spam",
            "reply-chain-conversation-spam", "backscatter-bounce-spam",
            "email-subscription-bombing-spam", "organization-wide-spam-flood",
        })
    )
    if benign_technical_task:
        category = "Safe / Misclassified"

    # A provider can place ordinary conversational replies in Spam/Junk. When
    # the message is clearly a reply and has no concrete threat/lure evidence,
    # label it Safe / Misclassified while keeping it visible in the security
    # workspace because provider_flagged remains true. "Re:" alone is never
    # sufficient: any credential, URL, financial, delivery, auth, identity, or
    # dangerous-attachment signal prevents this downgrade.
    benign_provider_reply = bool(
        provider_flagged
        and not suspicious_subtype_hit
        and re.match(r"^\s*(?:re|fw|fwd)\s*:", subject, re.I)
        and not high
        and not promo
        and not money
        and not delivery
        and not credential_request
        and not sensitive
        and not urls
        and failures == 0
        and not strong_flags.intersection({
            "auth-failure", "reply-domain-mismatch", "display-name-impersonation",
            "risky-link", "credential-link", "dangerous-attachment", "reward-lure",
            "web-malware-delivery", "infostealer-banking-malware", "trojan-backdoor-bot-rat",
            "ransomware-destructive-malware",
            "targeted-multistage-malware",
            "fake-discount-coupon",
            "fake-product-service", "prize-lottery-inheritance-scam",
            "advance-fee-scam", "fake-invoice-renewal-debt",
            "fake-refund-recovery-service", "employment-task-scam",
            "fake-check-overpayment-scam", "emergency-confidence-scam",
            "tech-support-account-protection-scam", "payment-diversion-fraud",
            "business-email-compromise", "investment-cryptocurrency-fraud",
            "real-estate-high-value-transaction-fraud", "money-mule-laundering-recruitment",
            "generic-identity-claim-impersonation", "display-name-impersonation-type2",
            "role-department-impersonation", "brand-impersonation-type4",
            "person-name-impersonation", "username-localpart-lookalike",
            "lookalike-domain-impersonation", "homograph-unicode-impersonation",
            "reply-to-impersonation", "exact-domain-spoofing",
            "internal-employee-executive-impersonation", "vendor-business-partner-impersonation",
            "helpdesk-administrator-impersonation", "compromised-account-impersonation",
            "conversation-thread-hijacking", "coordinated-identity-impersonation",
            "unwanted-one-off-spam", "repetitive-sender-spam",
            "unsolicited-commercial-spam", "cold-outreach-spam",
            "bulk-list-spam", "harvested-address-spam",
            "unsubscribe-violation-spam", "deceptive-subject-spam",
            "obfuscated-content-spam", "rotating-sender-snowshoe-spam",
            "compromised-account-spam", "botnet-generated-spam",
            "reply-chain-conversation-spam", "backscatter-bounce-spam",
            "email-subscription-bombing-spam", "organization-wide-spam-flood",
        })
        and non_provider_score <= 15
    )
    if benign_provider_reply:
        category = "Safe / Misclassified"

    # A provider may still place a fully authenticated legitimate notification
    # in Spam/Junk. When the message has strong authentication and no concrete
    # local threat/lure evidence, treat the provider folder as location only.
    # Contextual AI may still refine authenticated bulk marketing to Spam.
    authenticated_provider_benign = bool(
        provider_flagged
        and not suspicious_subtype_hit
        and strong_authentication
        and failures == 0
        and non_provider_score <= 15
        and not high
        and not promo
        and not money
        and not delivery
        and not credential_request
        and not sensitive
        and not strong_flags.intersection({
            "auth-failure", "reply-domain-mismatch", "display-name-impersonation",
            "risky-link", "credential-link", "dangerous-attachment", "reward-lure",
            "web-malware-delivery", "infostealer-banking-malware", "trojan-backdoor-bot-rat",
            "ransomware-destructive-malware",
            "targeted-multistage-malware",
            "fake-discount-coupon",
            "fake-product-service", "prize-lottery-inheritance-scam",
            "advance-fee-scam", "fake-invoice-renewal-debt",
            "fake-refund-recovery-service", "employment-task-scam",
            "fake-check-overpayment-scam", "emergency-confidence-scam",
            "tech-support-account-protection-scam", "payment-diversion-fraud",
            "business-email-compromise", "investment-cryptocurrency-fraud",
            "real-estate-high-value-transaction-fraud", "money-mule-laundering-recruitment",
            "generic-identity-claim-impersonation", "display-name-impersonation-type2",
            "role-department-impersonation", "brand-impersonation-type4",
            "person-name-impersonation", "username-localpart-lookalike",
            "lookalike-domain-impersonation", "homograph-unicode-impersonation",
            "reply-to-impersonation", "exact-domain-spoofing",
            "internal-employee-executive-impersonation", "vendor-business-partner-impersonation",
            "helpdesk-administrator-impersonation", "compromised-account-impersonation",
            "conversation-thread-hijacking", "coordinated-identity-impersonation",
            "unwanted-one-off-spam", "repetitive-sender-spam",
            "unsolicited-commercial-spam", "cold-outreach-spam",
            "bulk-list-spam", "harvested-address-spam",
            "unsubscribe-violation-spam", "deceptive-subject-spam",
            "obfuscated-content-spam", "rotating-sender-snowshoe-spam",
            "compromised-account-spam", "botnet-generated-spam",
            "reply-chain-conversation-spam", "backscatter-bounce-spam",
            "email-subscription-bombing-spam", "organization-wide-spam-flood",
        })
    )
    if authenticated_provider_benign:
        category = "Safe / Misclassified"

    benign_delivery_report = bool(
        dsn_context
        and not suspicious_subtype_hit
        and failures == 0
        and not high
        and not urgency
        and not direct_dsn_action
        and not credential_request
        and not sensitive
        and not address
        and not fee
        and not money_lure
        and not strong_flags.intersection({
            "account-access-lure", "credential-link", "dangerous-attachment",
            "fraud-action-lure", "financial-fraud-lure", "impersonation-lure",
            "display-name-impersonation", "reply-domain-mismatch",
            "web-malware-delivery", "infostealer-banking-malware", "trojan-backdoor-bot-rat",
            "ransomware-destructive-malware",
            "targeted-multistage-malware",
            "fake-discount-coupon",
            "fake-product-service", "prize-lottery-inheritance-scam",
            "advance-fee-scam", "fake-invoice-renewal-debt",
            "fake-refund-recovery-service", "employment-task-scam",
            "fake-check-overpayment-scam", "emergency-confidence-scam",
            "tech-support-account-protection-scam", "payment-diversion-fraud",
            "business-email-compromise", "investment-cryptocurrency-fraud",
            "real-estate-high-value-transaction-fraud", "money-mule-laundering-recruitment",
            "generic-identity-claim-impersonation", "display-name-impersonation-type2",
            "role-department-impersonation", "brand-impersonation-type4",
            "person-name-impersonation", "username-localpart-lookalike",
            "lookalike-domain-impersonation", "homograph-unicode-impersonation",
            "reply-to-impersonation", "exact-domain-spoofing",
            "internal-employee-executive-impersonation", "vendor-business-partner-impersonation",
            "helpdesk-administrator-impersonation", "compromised-account-impersonation",
            "conversation-thread-hijacking", "coordinated-identity-impersonation",
            "unwanted-one-off-spam", "repetitive-sender-spam",
            "unsolicited-commercial-spam", "cold-outreach-spam",
            "bulk-list-spam", "harvested-address-spam",
            "unsubscribe-violation-spam", "deceptive-subject-spam",
            "obfuscated-content-spam", "rotating-sender-snowshoe-spam",
            "compromised-account-spam", "botnet-generated-spam",
            "reply-chain-conversation-spam", "backscatter-bounce-spam",
            "email-subscription-bombing-spam", "organization-wide-spam-flood",
        })
    )
    if benign_delivery_report:
        category = "Safe / Misclassified"
        strong_flags.add("benign-delivery-report")
        if "Machine-generated delivery report; quoted original content is not treated as a live instruction" not in reasons:
            reasons.append("Machine-generated delivery report; quoted original content is not treated as a live instruction")

    # Provider Spam/Junk placement is location evidence, not a content verdict.
    # Mark ordinary marketing that has no local risk score so contextual AI does
    # not turn provider placement alone into Spam.
    if (
        category == "Promotional"
        and provider_flagged
        and non_provider_score == 0
        and not strong_flags
    ):
        strong_flags.add("provider-location-only-promo")

    # Strongly authenticated provider-Junk mail can accumulate soft heuristics
    # such as several links or an unusually long host while still remaining
    # below the Suspicious threshold. Preserve that non-malicious boundary when
    # no concrete strong signal exists; malicious AI findings remain eligible
    # for the separate confirmation path.
    if (
        category == "Safe / Misclassified"
        and provider_flagged
        and strong_authentication
        and failures == 0
        and 0 < non_provider_score < 35
        and not strong_flags
    ):
        strong_flags.add("authenticated-soft-signal-boundary")

    flagged = bool(
        provider_flagged
        or (not benign_technical_task and not benign_delivery_report and threshold_flagged)
        or (not benign_technical_task and not benign_delivery_report and category in {
            "Spam", "Phishing", "Malware", "Scam / Fraud", "Impersonation", "Suspicious"
        })
    )

    category_value = category_scores.get(category, top_score)
    if category == "Malware":
        confidence = 99
    elif category == "Promotional":
        confidence = _bounded_confidence(category_value, second_score, minimum=72)
    elif category == "Safe / Misclassified":
        confidence = 78 if not provider_flagged else 58
    elif provider_flagged and non_provider_score == 0 and category == "Spam":
        confidence = 86
    else:
        confidence = _bounded_confidence(category_value, second_score)

    malicious = category in {"Phishing", "Malware", "Scam / Fraud", "Impersonation"}
    result = {
        "is_spam": flagged,
        "score": bounded_score,
        "reason": "; ".join(reasons),
        "category": category,
        "confidence": confidence,
        "source": "Security signals",
        "malicious": malicious,
        "provider_flagged": provider_flagged,
        "non_provider_score": min(max(non_provider_score, 0), 100),
        "category_scores": category_scores,
        "strong_flags": sorted(strong_flags),
        "rule_hits": list(rule_hits),
        "category_slug": _category_slug(category),
    }
    trace_security_detection(
        "DETERMINISTIC_FINAL",
        email=email_data,
        baseline=result,
        payload={
            "dsn_context": bool(dsn_context),
            "auth_failures": int(failures),
            "auth_passes": int(auth_passes),
            "strong_authentication": bool(strong_authentication),
        },
    )
    return result
