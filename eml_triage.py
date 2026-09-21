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
from email.message import EmailMessage
from email.utils import parseaddr, getaddresses

__version__ = "1.0.0"

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
    to: list[str] = field(default_factory=list)
    auth_results: dict[str, str] = field(default_factory=dict)
    originating_ip: str = ""
    received_hops: int = 0
    urls: list[str] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
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
        elif ext in HTML_EXT:
            findings.append(Finding("high", "attachment-html", f"Lampiran HTML, pola halaman login palsu: {item.filename}"))
        elif ext in CONTAINER_EXT:
            findings.append(Finding("medium", "attachment-container", f"Lampiran berupa wadah arsip: {item.filename}"))

        # invoice.pdf.exe - ekstensi ganda untuk menipu mata.
        parts = name.split(".")
        if len(parts) >= 3 and parts[-2] in {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"}:
            findings.append(Finding("high", "attachment-double-ext", f"Ekstensi ganda menyesatkan: {item.filename}"))
    return findings


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
        to=[addr.lower() for _, addr in getaddresses([str(v) for v in msg.get_all("To", [])]) if addr],
        auth_results=parse_auth_results(msg),
        originating_ip=ip,
        received_hops=hops,
        urls=extract_urls(plain, html),
        attachments=extract_attachments(msg),
    )

    report.findings = (
        check_authentication(report.auth_results)
        + check_sender_alignment(report)
        + check_urls(report.urls, html)
        + check_attachments(report.attachments)
    )
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="eml-triage",
        description="Triase berkas .eml untuk analis SOC Level 1.",
    )
    parser.add_argument("files", nargs="+", help="satu atau beberapa berkas .eml")
    parser.add_argument("--json", action="store_true", help="keluarkan laporan sebagai JSON")
    parser.add_argument(
        "--fail-on-suspicious",
        action="store_true",
        help="kembalikan exit code 1 bila ada email yang mencurigakan",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    reports = []
    for path in args.files:
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
    else:
        print("\n\n".join(render_text(r) for r in reports))

    if args.fail_on_suspicious and any(r.verdict.startswith("SUSPICIOUS") for r in reports):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
