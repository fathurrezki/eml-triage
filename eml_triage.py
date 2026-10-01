#!/usr/bin/env python3
"""eml-triage - triase cepat file .eml seperti yang dilakukan analis SOC Level 1.

Membaca satu berkas email mentah (.eml), lalu memeriksa hal-hal yang biasa
ditanyakan saat menerima laporan phishing:

  - apakah SPF, DKIM, dan DMARC lolos
  - apakah domain From, Reply-To, dan Return-Path saling cocok
  - apakah nama tampilan pengirim menyamar sebagai alamat lain
  - dari IP mana email itu sebenarnya berasal
  - URL apa saja yang ada di badan email, dan apakah teks tautannya
    berbeda dari tujuan sebenarnya
  - lampiran apa saja yang ikut, beserta SHA-256-nya

Semua URL dan domain pada laporan ditulis dalam bentuk defanged
(hxxp://contoh[.]com) supaya aman ditempel ke tiket atau chat.

Hanya memakai pustaka standar Python. Tidak ada koneksi keluar:
berkas dibaca, dianalisis, selesai.
"""

from __future__ import annotations

import argparse
import email
import email.policy
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from email.message import EmailMessage
from email.utils import parseaddr, getaddresses

__version__ = "1.1.0"

# Ekstensi yang hampir tidak pernah wajar dikirim lewat email ke pengguna akhir.
EXECUTABLE_EXT = {
    "exe", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "ps1", "msi", "msp", "hta", "cpl", "jar", "lnk", "reg",
}
# Wadah yang sering dipakai untuk membungkus muatan di atas.
CONTAINER_EXT = {"iso", "img", "vhd", "vhdx", "cab", "ace", "arj", "7z", "rar", "zip"}
# Lampiran HTML dipakai untuk halaman login palsu yang dibuka secara lokal.
HTML_EXT = {"htm", "html", "shtml", "xhtml"}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "s.id", "bit.do", "shorturl.at",
}

URL_RE = re.compile(r"""https?://[^\s<>"')\]]+""", re.IGNORECASE)
ANCHOR_RE = re.compile(
    r"""<a\b[^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a>""",
    re.IGNORECASE | re.DOTALL,
)
TAG_RE = re.compile(r"<[^>]+>")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Dokumen Office dengan makro: jalur utama pengiriman loader/stealer.
MACRO_EXT = {"docm", "dotm", "xlsm", "xltm", "xlam", "xlsb", "pptm", "potm", "ppam", "sldm"}

# Merek yang paling sering ditiru pada phishing beserta domain sahnya.
BRANDS: dict[str, set[str]] = {
    "microsoft": {"microsoft.com", "office.com", "office365.com", "outlook.com",
                  "live.com", "microsoftonline.com", "sharepoint.com"},
    "google": {"google.com", "gmail.com", "googlemail.com"},
    "apple": {"apple.com", "icloud.com"},
    "paypal": {"paypal.com"},
    "amazon": {"amazon.com", "amazon.co.id", "amazonses.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"},
    "linkedin": {"linkedin.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dropbox": {"dropbox.com"},
    "adobe": {"adobe.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "shopee": {"shopee.co.id", "shopee.com"},
    "tokopedia": {"tokopedia.com"},
    "bca": {"bca.co.id", "klikbca.com"},
    "mandiri": {"bankmandiri.co.id"},
    "bni": {"bni.co.id"},
    "bri": {"bri.co.id"},
}
LEGIT_DOMAINS = {d for domains in BRANDS.values() for d in domains}

# Angka/simbol yang dipakai meniru huruf. i, l, dan 1 dilebur jadi satu supaya
# paypa1 dan m1crosoft sama-sama terbaca; merek pun dinormalkan dengan peta ini.
HOMOGLYPHS = str.maketrans({"0": "o", "1": "i", "l": "i", "|": "i", "3": "e",
                            "4": "a", "@": "a", "5": "s", "$": "s", "7": "t"})

# Kata pemicu rasa panik. Satu kata saja lumrah, dua ke atas baru dicatat.
LURE_TERMS = (
    "verifikasi", "verify", "verification", "suspended", "diblokir", "dibekukan",
    "segera", "urgent", "immediately", "action required", "tindakan diperlukan",
    "kedaluwarsa", "expired", "kata sandi", "password", "konfirmasi ulang",
    "reactivate", "aktifkan kembali", "dalam 24 jam", "within 24 hours",
)

FORM_ACTION_RE = re.compile(r"""<form\b[^>]*\baction\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
FORM_RE = re.compile(r"<form\b", re.IGNORECASE)
PASSWORD_INPUT_RE = re.compile(r"""<input\b[^>]*\btype\s*=\s*["']?password""", re.IGNORECASE)
SCRIPT_RE = re.compile(r"<script\b", re.IGNORECASE)
META_REFRESH_RE = re.compile(r"""<meta\b[^>]*http-equiv\s*=\s*["']?refresh""", re.IGNORECASE)
IMG_RE = re.compile(r"<img\b[^>]*>", re.IGNORECASE)
DIMENSION_RE = re.compile(r"""\b(width|height)\s*[=:]\s*["']?\s*(\d+)""", re.IGNORECASE)
DATA_URI_RE = re.compile(r"""\b(?:href|src|action)\s*=\s*["']\s*(data:[^"']{10,})""", re.IGNORECASE)
HIDDEN_STYLE_RE = re.compile(
    r"(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt)?\b"
    r"|opacity\s*:\s*0(?:\.0+)?\b)",
    re.IGNORECASE,
)

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


# --------------------------------------------------------------------------
# struktur data
# --------------------------------------------------------------------------

@dataclass
class Finding:
    """Satu temuan hasil pemeriksaan."""

    severity: str
    rule: str
    detail: str


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str


@dataclass
class Report:
    source: str
    subject: str = ""
    message_id: str = ""
    date: str = ""
    from_address: str = ""
    from_display: str = ""
    reply_to: str = ""
    return_path: str = ""
    in_reply_to: str = ""
    references: str = ""
    to: list[str] = field(default_factory=list)
    auth_results: dict[str, str] = field(default_factory=dict)
    originating_ip: str = ""
    received_hops: int = 0
    urls: list[str] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    iocs: dict[str, list[str]] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    verdict: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------
# utilitas
# --------------------------------------------------------------------------

def defang(value: str) -> str:
    """Menonaktifkan URL/domain agar tidak bisa diklik saat ditempel ke tiket."""
    return value.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")


def domain_of(address: str) -> str:
    """Mengambil domain dari sebuah alamat email."""
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].strip().strip(">").lower()


def registrable(domain: str) -> str:
    """Perkiraan kasar domain terdaftar: dua label terakhir.

    Cukup untuk membandingkan From dengan Reply-To. Untuk ccTLD bertingkat
    seperti co.id, gunakan daftar suffix publik kalau butuh presisi.
    """
    parts = [p for p in domain.lower().split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    if parts[-2] in {"co", "or", "ac", "go", "net", "com", "sch", "web", "my", "biz"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def host_of(url: str) -> str:
    """Mengambil host dari URL tanpa memakai urllib (menghindari normalisasi)."""
    stripped = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)
    stripped = stripped.split("/", 1)[0]
    stripped = stripped.split("?", 1)[0]
    if "@" in stripped:                      # buang userinfo: user@host
        stripped = stripped.rsplit("@", 1)[1]
    if stripped.startswith("["):             # IPv6 literal
        return stripped.split("]", 1)[0] + "]"
    return stripped.split(":", 1)[0].lower()


def canonical(text: str) -> str:
    """Menyederhanakan teks agar tiruan seperti "M1cr0s0ft" tetap terbaca."""
    return re.sub(r"[^a-z]", "", text.lower().translate(HOMOGLYPHS))


def edit_distance(a: str, b: str, cap: int = 2) -> int:
    """Jarak Levenshtein yang berhenti begitu melewati cap (hemat waktu)."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > cap:
            return cap + 1
        prev = cur
    return prev[-1]


def brands_in(text: str) -> list[str]:
    """Merek yang disebut pada sebuah teks (nama tampilan, domain, subjek)."""
    if not text:
        return []
    low = text.lower()
    canon = canonical(text)
    hits = []
    for brand in BRANDS:
        if len(brand) <= 4:                  # bca, bni, bri, dhl: harus kata utuh
            if re.search(rf"\b{re.escape(brand)}\b", low):
                hits.append(brand)
        elif canonical(brand) in canon:
            hits.append(brand)
    return hits


def lookalike_of(domain: str) -> tuple[str, int]:
    """Domain merek yang paling mirip dengan domain ini, bila memang mirip."""
    if not domain or domain in LEGIT_DOMAINS:
        return "", 0
    for legit in sorted(LEGIT_DOMAINS):
        cap = 1 if len(legit) <= 11 else 2
        distance = edit_distance(domain, legit, cap)
        if 0 < distance <= cap:
            return legit, distance
    return "", 0


def extension_of(filename: str) -> str:
    return filename.rsplit(".", 1)[1].lower() if "." in filename else ""


# --------------------------------------------------------------------------
# pengurai bagian-bagian email
# --------------------------------------------------------------------------

def parse_auth_results(msg: EmailMessage) -> dict[str, str]:
    """Membaca hasil SPF, DKIM, dan DMARC dari header Authentication-Results."""
    results: dict[str, str] = {}
    raw = " ".join(str(v) for v in msg.get_all("Authentication-Results", []))
    raw += " " + " ".join(str(v) for v in msg.get_all("Received-SPF", []))
    for mech in ("spf", "dkim", "dmarc"):
        match = re.search(rf"\b{mech}\s*=\s*([a-z]+)", raw, re.IGNORECASE)
        if match:
            results[mech] = match.group(1).lower()
    if "spf" not in results:
        spf_header = " ".join(str(v) for v in msg.get_all("Received-SPF", []))
        match = re.match(r"\s*([a-z]+)", spf_header, re.IGNORECASE)
        if match:
            results["spf"] = match.group(1).lower()
    return results


def originating_ip(msg: EmailMessage) -> tuple[str, int]:
    """Mengambil IP publik pertama dari rantai Received (hop paling awal)."""
    received = [str(v) for v in msg.get_all("Received", [])]
    if not received:
        return "", 0
    for header in reversed(received):        # hop paling awal ada di urutan terakhir
        for candidate in IPV4_RE.findall(header):
            if not is_private_ip(candidate):
                return candidate, len(received)
    return "", len(received)


def is_private_ip(ip: str) -> bool:
    try:
        octets = [int(o) for o in ip.split(".")]
    except ValueError:
        return True
    if len(octets) != 4 or any(o > 255 for o in octets):
        return True
    if octets[0] == 10 or octets[0] == 127:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 169 and octets[1] == 254:
        return True
    return False


def body_parts(msg: EmailMessage) -> tuple[str, str]:
    """Mengembalikan pasangan (teks polos, teks HTML) dari badan email."""
    plain, html = [], []
    for part in msg.walk():
        if part.get_content_maintype() != "text":
            continue
        if part.get_filename():              # itu lampiran, bukan badan
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeDecodeError):
            payload = part.get_payload(decode=True) or b""
            content = payload.decode("utf-8", "replace")
        if part.get_content_subtype() == "html":
            html.append(content)
        else:
            plain.append(content)
    return "\n".join(plain), "\n".join(html)


def extract_urls(plain: str, html: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for chunk in (plain, html):
        for url in URL_RE.findall(chunk):
            url = url.rstrip(".,;:!)\"'")
            if url not in seen:
                seen.add(url)
                found.append(url)
    return found


def extract_attachments(msg: EmailMessage) -> list[Attachment]:
    items: list[Attachment] = []
    for part in msg.walk():
        filename = part.get_filename()
        if not filename:
            continue
        payload = part.get_payload(decode=True) or b""
        items.append(
            Attachment(
                filename=filename,
                content_type=part.get_content_type(),
                size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
            )
        )
    return items


# --------------------------------------------------------------------------
# aturan pemeriksaan
# --------------------------------------------------------------------------

def check_authentication(auth: dict[str, str]) -> list[Finding]:
    findings = []
    spf = auth.get("spf")
    if spf in {"fail", "softfail"}:
        findings.append(Finding("high", "spf-fail", f"SPF {spf}: pengirim tidak diizinkan domain From"))
    elif spf in {"none", "neutral", "permerror", "temperror"}:
        findings.append(Finding("medium", "spf-weak", f"SPF {spf}: domain tidak menyatakan pengirim sah"))
    elif spf is None:
        findings.append(Finding("low", "spf-missing", "Tidak ada hasil SPF pada header"))

    dkim = auth.get("dkim")
    if dkim == "fail":
        findings.append(Finding("high", "dkim-fail", "DKIM fail: isi atau header email berubah di perjalanan"))
    elif dkim in {"none", "permerror", "temperror"} or dkim is None:
        findings.append(Finding("medium", "dkim-missing", "Email tidak ditandatangani DKIM yang sah"))

    dmarc = auth.get("dmarc")
    if dmarc == "fail":
        findings.append(Finding("high", "dmarc-fail", "DMARC fail: pengirim gagal membuktikan identitas domain"))
    elif dmarc is None:
        findings.append(Finding("low", "dmarc-missing", "Tidak ada hasil DMARC pada header"))
    return findings


def check_sender_alignment(report: Report) -> list[Finding]:
    findings = []
    from_domain = registrable(domain_of(report.from_address))
    if not from_domain:
        return findings

    if report.reply_to:
        reply_domain = registrable(domain_of(report.reply_to))
        if reply_domain and reply_domain != from_domain:
            findings.append(
                Finding(
                    "medium",
                    "replyto-mismatch",
                    f"Reply-To mengarah ke {defang(reply_domain)}, bukan {defang(from_domain)}",
                )
            )

    if report.return_path:
        rp_domain = registrable(domain_of(report.return_path))
        if rp_domain and rp_domain != from_domain:
            findings.append(
                Finding(
                    "medium",
                    "returnpath-mismatch",
                    f"Return-Path memakai {defang(rp_domain)}, bukan {defang(from_domain)}",
                )
            )

    # Nama tampilan yang memuat alamat email lain adalah taktik penyamaran klasik.
    embedded = re.search(r"[\w.+-]+@[\w.-]+\.\w+", report.from_display or "")
    if embedded and embedded.group(0).lower() != report.from_address.lower():
        findings.append(
            Finding(
                "high",
                "display-name-spoof",
                f"Nama tampilan menulis {defang(embedded.group(0))} padahal pengirim asli {defang(report.from_address)}",
            )
        )
    return findings


def check_urls(urls: list[str], html: str) -> list[Finding]:
    findings = []
    for url in urls:
        host = host_of(url)
        if IPV4_RE.fullmatch(host):
            findings.append(Finding("high", "url-ip-literal", f"Tautan menuju alamat IP langsung: {defang(url)}"))
        if host.startswith("xn--") or ".xn--" in host:
            findings.append(Finding("high", "url-punycode", f"Host memakai punycode (kemungkinan homograf): {defang(host)}"))
        if host in SHORTENER_DOMAINS:
            findings.append(Finding("medium", "url-shortener", f"Tautan disamarkan lewat pemendek URL: {defang(url)}"))
        if url.lower().startswith("http://"):
            findings.append(Finding("low", "url-plaintext", f"Tautan tidak terenkripsi: {defang(url)}"))

    # Teks tautan yang menampilkan satu domain tetapi mengarah ke domain lain.
    for href, text in ANCHOR_RE.findall(html):
        label = TAG_RE.sub("", text).strip()
        if not label:
            continue
        label_host = host_of(label) if label.lower().startswith(("http://", "https://")) else ""
        if not label_host and re.fullmatch(r"[\w.-]+\.\w{2,}", label):
            label_host = label.lower()
        if not label_host:
            continue
        href_host = host_of(href)
        if href_host and registrable(label_host) != registrable(href_host):
            findings.append(
                Finding(
                    "high",
                    "link-text-mismatch",
                    f"Teks tautan menulis {defang(label_host)} tetapi menuju {defang(href_host)}",
                )
            )
    return findings


def check_attachments(attachments: list[Attachment]) -> list[Finding]:
    findings = []
    for item in attachments:
        ext = extension_of(item.filename)
        name = item.filename.lower()

        if ext in EXECUTABLE_EXT:
            findings.append(Finding("high", "attachment-executable", f"Lampiran dapat dieksekusi: {item.filename}"))
        elif ext in MACRO_EXT:
            findings.append(Finding("high", "attachment-macro", f"Dokumen Office bermakro: {item.filename}"))
        elif ext in HTML_EXT:
            findings.append(Finding("high", "attachment-html", f"Lampiran HTML, pola halaman login palsu: {item.filename}"))
        elif ext in CONTAINER_EXT:
            findings.append(Finding("medium", "attachment-container", f"Lampiran berupa wadah arsip: {item.filename}"))

        # invoice.pdf.exe - ekstensi ganda untuk menipu mata.
        parts = name.split(".")
        if len(parts) >= 3 and parts[-2] in {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"}:
            findings.append(Finding("high", "attachment-double-ext", f"Ekstensi ganda menyesatkan: {item.filename}"))
    return findings


def check_brand(report: Report) -> list[Finding]:
    """Penyamaran merek: nama tampilan, nama merek di domain, dan domain tiruan."""
    findings = []
    from_domain = registrable(domain_of(report.from_address))
    if not from_domain:
        return findings

    for brand in brands_in(report.from_display):
        if from_domain not in BRANDS[brand]:
            findings.append(
                Finding(
                    "high",
                    "brand-impersonation",
                    f"Nama tampilan mengaku {brand.title()} tetapi domain pengirim {defang(from_domain)}",
                )
            )

    for brand in brands_in(domain_of(report.from_address)):
        if from_domain not in BRANDS[brand]:
            findings.append(
                Finding(
                    "high",
                    "brand-in-domain",
                    f"Nama {brand.title()} dipasang pada domain asing {defang(from_domain)}",
                )
            )

    legit, distance = lookalike_of(from_domain)
    if legit:
        findings.append(
            Finding(
                "high",
                "lookalike-domain",
                f"Domain pengirim {defang(from_domain)} mirip {defang(legit)} (beda {distance} karakter)",
            )
        )

    checked: set[str] = set()
    for url in report.urls:
        host = host_of(url)
        if not host or host in checked or IPV4_RE.fullmatch(host):
            continue
        checked.add(host)
        base = registrable(host)
        legit, distance = lookalike_of(base)
        if legit:
            findings.append(
                Finding(
                    "high",
                    "lookalike-url",
                    f"Host tautan {defang(base)} mirip {defang(legit)} (beda {distance} karakter)",
                )
            )
            continue
        for brand in brands_in(host):
            if base not in BRANDS[brand]:
                findings.append(
                    Finding(
                        "high",
                        "brand-in-url",
                        f"Nama {brand.title()} dipasang pada host tautan {defang(host)}",
                    )
                )
    return findings


def check_html_body(html: str) -> list[Finding]:
    """Isi HTML: formulir pencuri kredensial, skrip, pengalihan, teks tersembunyi."""
    findings = []
    if not html:
        return findings

    for action in FORM_ACTION_RE.findall(html):
        if action.lower().startswith(("http://", "https://")):
            findings.append(
                Finding(
                    "high",
                    "html-form-external",
                    f"Badan email memuat formulir yang mengirim isian ke {defang(host_of(action))}",
                )
            )
        elif action.lower().startswith("data:"):
            findings.append(Finding("high", "html-form-external", "Formulir mengarah ke data: URI"))
    if FORM_RE.search(html) and not FORM_ACTION_RE.search(html):
        findings.append(Finding("medium", "html-form", "Badan email memuat formulir tanpa tujuan yang jelas"))
    if PASSWORD_INPUT_RE.search(html):
        findings.append(Finding("high", "html-password-input", "Ada kolom kata sandi langsung di badan email"))
    if SCRIPT_RE.search(html):
        findings.append(Finding("high", "html-script", "Badan email memuat <script>"))
    if META_REFRESH_RE.search(html):
        findings.append(Finding("high", "html-meta-refresh", "Badan email memaksa pengalihan otomatis (meta refresh)"))
    for uri in DATA_URI_RE.findall(html):
        findings.append(Finding("high", "html-data-uri", f"Tautan/sumber berupa data: URI ({uri[:40]}...)"))

    if HIDDEN_STYLE_RE.search(html):
        findings.append(Finding("medium", "html-hidden-text", "Ada teks yang disembunyikan dari pembaca"))

    for tag in IMG_RE.findall(html):
        dims = {k.lower(): int(v) for k, v in DIMENSION_RE.findall(tag)}
        if dims.get("width", 99) <= 1 and dims.get("height", 99) <= 1:
            findings.append(Finding("low", "tracking-pixel", "Ada piksel pelacak 1x1 di badan email"))
            break
    return findings


def check_headers(report: Report) -> list[Finding]:
    """Header non-autentikasi: balasan palsu, Message-ID, dan subjek pemancing."""
    findings = []
    subject = report.subject or ""

    if re.match(r"\s*(re|fw|fwd)\s*:", subject, re.IGNORECASE) and not (
        report.in_reply_to or report.references
    ):
        findings.append(
            Finding("medium", "thread-spoof", "Subjek mengaku balasan tetapi tidak ada In-Reply-To/References")
        )

    if not report.message_id:
        findings.append(Finding("medium", "messageid-missing", "Tidak ada Message-ID: lazim pada email hasil skrip"))
    else:
        mid_domain = registrable(domain_of(report.message_id.strip("<>")))
        from_domain = registrable(domain_of(report.from_address))
        if mid_domain and from_domain and mid_domain != from_domain:
            findings.append(
                Finding(
                    "low",
                    "messageid-mismatch",
                    f"Message-ID dibuat di {defang(mid_domain)}, bukan {defang(from_domain)}",
                )
            )

    low_subject = subject.lower()
    hits = [term for term in LURE_TERMS if term in low_subject]
    if len(hits) >= 2:
        findings.append(
            Finding("low", "subject-lure", "Subjek memakai kata pemancing: " + ", ".join(hits[:4]))
        )
    return findings


def collect_iocs(report: Report) -> dict[str, list[str]]:
    """IOC siap tempel ke tiket atau blocklist."""
    hosts: set[str] = set()
    ips: set[str] = set()
    emails = {a for a in (report.from_address, report.reply_to, report.return_path) if a}

    for url in report.urls:
        host = host_of(url)
        if not host:
            continue
        if IPV4_RE.fullmatch(host):
            ips.add(host)
        else:
            hosts.add(host)
    if report.originating_ip:
        ips.add(report.originating_ip)
    for address in list(emails):
        domain = domain_of(address)
        if domain:
            hosts.add(domain)

    return {
        "urls": sorted(set(report.urls)),
        "domains": sorted(hosts),
        "ips": sorted(ips),
        "emails": sorted(emails),
        "sha256": sorted({a.sha256 for a in report.attachments}),
    }


def decide(findings: list[Finding]) -> str:
    high = sum(1 for f in findings if f.severity == "high")
    medium = sum(1 for f in findings if f.severity == "medium")
    if high:
        return "SUSPICIOUS - eskalasi ke L2"
    if medium >= 2:
        return "SUSPICIOUS - perlu pemeriksaan lanjutan"
    if medium == 1:
        return "PERLU DIPERIKSA - satu indikator lemah"
    return "KEMUNGKINAN AMAN - tidak ada indikator kuat"


# --------------------------------------------------------------------------
# alur utama
# --------------------------------------------------------------------------

def analyze(raw: bytes, source: str = "-") -> Report:
    """Menganalisis satu email mentah dan mengembalikan laporan triase."""
    msg: EmailMessage = email.message_from_bytes(raw, policy=email.policy.default)

    from_display, from_address = parseaddr(str(msg.get("From", "")))
    _, reply_to = parseaddr(str(msg.get("Reply-To", "")))
    _, return_path = parseaddr(str(msg.get("Return-Path", "")))

    plain, html = body_parts(msg)
    ip, hops = originating_ip(msg)

    report = Report(
        source=source,
        subject=str(msg.get("Subject", "")),
        message_id=str(msg.get("Message-ID", "")),
        date=str(msg.get("Date", "")),
        from_address=from_address.lower(),
        from_display=from_display,
        reply_to=reply_to.lower(),
        return_path=return_path.lower(),
        in_reply_to=str(msg.get("In-Reply-To", "")),
        references=str(msg.get("References", "")),
        to=[addr.lower() for _, addr in getaddresses([str(v) for v in msg.get_all("To", [])]) if addr],
        auth_results=parse_auth_results(msg),
        originating_ip=ip,
        received_hops=hops,
        urls=extract_urls(plain, html),
        attachments=extract_attachments(msg),
    )

    report.iocs = collect_iocs(report)
    raw_findings = (
        check_authentication(report.auth_results)
        + check_sender_alignment(report)
        + check_brand(report)
        + check_headers(report)
        + check_urls(report.urls, html)
        + check_html_body(html)
        + check_attachments(report.attachments)
    )
    seen: set[tuple[str, str, str]] = set()
    for finding in raw_findings:            # aturan berbeda bisa menunjuk hal yang sama
        key = (finding.severity, finding.rule, finding.detail)
        if key not in seen:
            seen.add(key)
            report.findings.append(finding)
    report.findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    report.verdict = decide(report.findings)
    return report


def render_text(report: Report) -> str:
    lines = []
    add = lines.append

    add("=" * 68)
    add(f"  TRIASE EMAIL  -  {report.source}")
    add("=" * 68)
    add(f"Subject      : {report.subject}")
    add(f"Tanggal      : {report.date}")
    add(f"From         : {report.from_display} <{defang(report.from_address)}>")
    if report.reply_to:
        add(f"Reply-To     : {defang(report.reply_to)}")
    if report.return_path:
        add(f"Return-Path  : {defang(report.return_path)}")
    if report.to:
        add(f"To           : {', '.join(defang(a) for a in report.to)}")
    add(f"Message-ID   : {report.message_id}")

    add("")
    add("-- Autentikasi " + "-" * 53)
    if report.auth_results:
        for mech in ("spf", "dkim", "dmarc"):
            add(f"{mech.upper():<6}: {report.auth_results.get(mech, 'tidak ada')}")
    else:
        add("Tidak ada header Authentication-Results")
    add(f"Asal IP: {defang(report.originating_ip) if report.originating_ip else 'tidak ditemukan'}"
        f"   (rantai Received: {report.received_hops} hop)")

    add("")
    add(f"-- URL ({len(report.urls)}) " + "-" * 56)
    for url in report.urls:
        add(f"  {defang(url)}")
    if not report.urls:
        add("  tidak ada")

    add("")
    add(f"-- Lampiran ({len(report.attachments)}) " + "-" * 51)
    for item in report.attachments:
        add(f"  {item.filename}  [{item.content_type}, {item.size} B]")
        add(f"    sha256: {item.sha256}")
    if not report.attachments:
        add("  tidak ada")

    add("")
    add(f"-- Temuan ({len(report.findings)}) " + "-" * 53)
    if report.findings:
        for f in report.findings:
            add(f"  [{f.severity.upper():<6}] {f.rule}")
            add(f"           {f.detail}")
    else:
        add("  tidak ada indikator mencurigakan")

    add("")
    add("=" * 68)
    add(f"  VERDICT: {report.verdict}")
    add("=" * 68)
    return "\n".join(lines)


def render_iocs(reports: list[Report], raw: bool = False) -> str:
    """Daftar IOC gabungan, satu nilai per baris, siap disalin ke tiket."""
    merged: dict[str, set[str]] = {}
    for report in reports:
        for key, values in report.iocs.items():
            merged.setdefault(key, set()).update(values)

    labels = {"urls": "URL", "domains": "DOMAIN", "ips": "IP",
              "emails": "ALAMAT EMAIL", "sha256": "SHA256 LAMPIRAN"}
    lines: list[str] = []
    for key in ("urls", "domains", "ips", "emails", "sha256"):
        values = sorted(merged.get(key, set()))
        if not values:
            continue
        lines.append(f"# {labels[key]} ({len(values)})")
        for value in values:
            lines.append(value if raw or key == "sha256" else defang(value))
        lines.append("")
    return "\n".join(lines).rstrip()


def render_summary(reports: list[Report]) -> str:
    """Satu baris per berkas: jumlah temuan per tingkat lalu verdict."""
    lines = [f"{'BERKAS':<32} {'H':>2} {'M':>2} {'L':>2}  VERDICT", "-" * 78]
    for report in reports:
        counts = {
            level: sum(1 for f in report.findings if f.severity == level)
            for level in ("high", "medium", "low")
        }
        name = Path(report.source).name
        if len(name) > 32:
            name = name[:29] + "..."
        lines.append(
            f"{name:<32} {counts['high']:>2} {counts['medium']:>2} {counts['low']:>2}  {report.verdict}"
        )
    return "\n".join(lines)


def expand_paths(paths: list[str]) -> list[str]:
    """Folder diperlakukan sebagai kumpulan .eml di dalamnya (tidak rekursif)."""
    expanded: list[str] = []
    for item in paths:
        path = Path(item)
        if path.is_dir():
            expanded.extend(
                str(child) for child in sorted(path.iterdir())
                if child.is_file() and child.suffix.lower() == ".eml"
            )
        else:
            expanded.append(item)
    return expanded


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="eml-triage",
        description="Triase berkas .eml untuk analis SOC Level 1.",
    )
    parser.add_argument("files", nargs="+", help="berkas .eml, atau folder berisi berkas .eml")
    parser.add_argument("--json", action="store_true", help="keluarkan laporan sebagai JSON")
    parser.add_argument("--iocs", action="store_true",
                        help="cetak hanya daftar IOC (URL, domain, IP, alamat, hash)")
    parser.add_argument("--raw", action="store_true",
                        help="jangan defang IOC, untuk diimpor ke blocklist")
    parser.add_argument("--summary", action="store_true",
                        help="satu baris verdict per berkas, cocok untuk banyak berkas")
    parser.add_argument(
        "--fail-on-suspicious",
        action="store_true",
        help="kembalikan exit code 1 bila ada email yang mencurigakan",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    files = expand_paths(args.files)
    if not files:
        print("tidak ada berkas .eml yang cocok", file=sys.stderr)
        return 2

    reports = []
    for path in files:
        try:
            with open(path, "rb") as handle:
                raw = handle.read()
        except OSError as exc:
            print(f"tidak bisa membaca {path}: {exc}", file=sys.stderr)
            return 2
        reports.append(analyze(raw, source=path))

    if args.json:
        payload = [r.to_dict() for r in reports]
        print(json.dumps(payload if len(payload) > 1 else payload[0], indent=2, ensure_ascii=False))
    elif args.iocs:
        print(render_iocs(reports, raw=args.raw))
    elif args.summary:
        print(render_summary(reports))
    else:
        print("\n\n".join(render_text(r) for r in reports))

    if args.fail_on_suspicious and any(r.verdict.startswith("SUSPICIOUS") for r in reports):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
