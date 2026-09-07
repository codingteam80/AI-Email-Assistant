# Safe outbound email formatting shared by SMTP and Microsoft Graph.
import html
import re


def normalize_plain_text(value: str) -> str:
    # Normalize editor newlines without changing its visible paragraph layout.
    return str(value or "").replace("\r\n", "\n").replace("\r", "\n").strip()


def plain_text_to_html(value: str) -> str:
    # Convert an edited plain-text draft into email-safe paragraph HTML.
    text = normalize_plain_text(value)
    if not text:
        return ""
    paragraphs = re.split(r"\n[ \t]*\n+", text)
    rendered = []
    for index, paragraph in enumerate(paragraphs):
        content = html.escape(paragraph, quote=True).replace("\n", "<br>\n")
        margin = "0" if index == len(paragraphs) - 1 else "0 0 1em 0"
        rendered.append(f'<p style="margin:{margin}">{content}</p>')
    return (
        '<div style="font-family:Arial,Helvetica,sans-serif;'
        'font-size:14px;line-height:1.5;color:#202124">'
        + "".join(rendered)
        + "</div>"
    )


