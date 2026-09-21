"""Uji unit untuk eml-triage. Jalankan: python -m unittest discover -s tests"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eml_triage import (  # noqa: E402
    Attachment,
    Finding,
    analyze,
    check_attachments,
    check_urls,
    decide,
    defang,
    extension_of,
    host_of,
    is_private_ip,
    registrable,
)

SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")


def read_sample(name):
    with open(os.path.join(SAMPLES, name), "rb") as handle:
        return handle.read()


def rules(report):
    return {f.rule for f in report.findings}


class TestHelpers(unittest.TestCase):
    def test_defang_menonaktifkan_skema_dan_titik(self):
        self.assertEqual(defang("http://evil.com/a"), "hxxp://evil[.]com/a")
        self.assertEqual(defang("https://evil.com"), "hxxps://evil[.]com")

    def test_registrable_menangani_ccTLD_bertingkat(self):
        self.assertEqual(registrable("ibank.bankexample.co.id"), "bankexample.co.id")
        self.assertEqual(registrable("mail.example.ru"), "example.ru")
        self.assertEqual(registrable("example.org"), "example.org")
        self.assertEqual(registrable("localhost"), "localhost")

    def test_host_of_membuang_userinfo_port_dan_path(self):
        self.assertEqual(host_of("https://user@evil.com:8443/login?a=1"), "evil.com")
        self.assertEqual(host_of("http://198.51.100.42/x"), "198.51.100.42")
        self.assertEqual(host_of("https://[2001:db8::1]/x"), "[2001:db8::1]")

    def test_is_private_ip(self):
        for ip in ("10.0.0.1", "192.168.1.5", "172.16.0.9", "127.0.0.1", "169.254.1.1"):
            self.assertTrue(is_private_ip(ip), ip)
        for ip in ("203.0.113.77", "8.8.8.8"):
            self.assertFalse(is_private_ip(ip), ip)
        self.assertTrue(is_private_ip("bukan-ip"))

    def test_extension_of(self):
        self.assertEqual(extension_of("invoice.pdf.exe"), "exe")
        self.assertEqual(extension_of("tanpa-ekstensi"), "")


class TestAturanURL(unittest.TestCase):
    def test_ip_literal_dan_http_polos(self):
        found = {f.rule for f in check_urls(["http://198.51.100.42/login"], "")}
        self.assertIn("url-ip-literal", found)
        self.assertIn("url-plaintext", found)

    def test_punycode_terdeteksi(self):
        found = {f.rule for f in check_urls(["https://xn--80ak6aa92e.com/"], "")}
        self.assertIn("url-punycode", found)

    def test_pemendek_url_terdeteksi(self):
        found = {f.rule for f in check_urls(["https://bit.ly/abc"], "")}
        self.assertIn("url-shortener", found)

    def test_teks_tautan_berbeda_dari_tujuan(self):
        html = '<a href="https://evil.example.net/login">https://bank.example.org/login</a>'
        found = {f.rule for f in check_urls([], html)}
        self.assertIn("link-text-mismatch", found)

    def test_teks_tautan_sama_tidak_memicu_temuan(self):
        html = '<a href="https://bank.example.org/login">https://bank.example.org/login</a>'
        found = {f.rule for f in check_urls([], html)}
        self.assertNotIn("link-text-mismatch", found)

    def test_subdomain_berbeda_tidak_dianggap_mismatch(self):
        html = '<a href="https://login.example.org/x">example.org</a>'
        found = {f.rule for f in check_urls([], html)}
        self.assertNotIn("link-text-mismatch", found)


class TestAturanLampiran(unittest.TestCase):
    def _att(self, name, ctype="application/octet-stream"):
        return Attachment(filename=name, content_type=ctype, size=10, sha256="0" * 64)

    def test_lampiran_eksekusi(self):
        found = {f.rule for f in check_attachments([self._att("update.exe")])}
        self.assertIn("attachment-executable", found)

    def test_lampiran_html(self):
        found = {f.rule for f in check_attachments([self._att("form.html", "text/html")])}
        self.assertIn("attachment-html", found)

    def test_ekstensi_ganda(self):
        found = {f.rule for f in check_attachments([self._att("invoice.pdf.exe")])}
        self.assertIn("attachment-double-ext", found)
        self.assertIn("attachment-executable", found)

    def test_lampiran_wajar_tidak_memicu_temuan(self):
        self.assertEqual(check_attachments([self._att("laporan.pdf", "application/pdf")]), [])


class TestVerdict(unittest.TestCase):
    def test_satu_high_langsung_eskalasi(self):
        self.assertTrue(decide([Finding("high", "x", "")]).startswith("SUSPICIOUS"))

    def test_dua_medium_dianggap_mencurigakan(self):
        verdict = decide([Finding("medium", "a", ""), Finding("medium", "b", "")])
        self.assertTrue(verdict.startswith("SUSPICIOUS"))

    def test_satu_medium_hanya_perlu_diperiksa(self):
        self.assertTrue(decide([Finding("medium", "a", "")]).startswith("PERLU DIPERIKSA"))

    def test_tanpa_temuan_dianggap_aman(self):
        self.assertTrue(decide([]).startswith("KEMUNGKINAN AMAN"))


class TestSampelPhishing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = analyze(read_sample("phishing.eml"), "phishing.eml")

    def test_verdict_eskalasi(self):
        self.assertTrue(self.report.verdict.startswith("SUSPICIOUS"))

    def test_autentikasi_gagal_semua(self):
        self.assertEqual(self.report.auth_results.get("spf"), "fail")
        self.assertEqual(self.report.auth_results.get("dkim"), "fail")
        self.assertEqual(self.report.auth_results.get("dmarc"), "fail")

    def test_nama_tampilan_menyamar(self):
        self.assertIn("display-name-spoof", rules(self.report))

    def test_domain_reply_to_dan_return_path_tidak_cocok(self):
        self.assertIn("replyto-mismatch", rules(self.report))
        self.assertIn("returnpath-mismatch", rules(self.report))

    def test_ip_asal_melewati_hop_privat(self):
        self.assertEqual(self.report.originating_ip, "203.0.113.77")

    def test_lampiran_berbahaya_terdeteksi(self):
        self.assertEqual(len(self.report.attachments), 1)
        self.assertIn("attachment-html", rules(self.report))
        self.assertIn("attachment-double-ext", rules(self.report))

    def test_sha256_lampiran_dihitung(self):
        self.assertRegex(self.report.attachments[0].sha256, r"^[0-9a-f]{64}$")

    def test_semua_url_terkumpul(self):
        self.assertEqual(len(self.report.urls), 3)


class TestSampelAman(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = analyze(read_sample("legitimate.eml"), "legitimate.eml")

    def test_tanpa_temuan(self):
        self.assertEqual(self.report.findings, [])

    def test_verdict_aman(self):
        self.assertTrue(self.report.verdict.startswith("KEMUNGKINAN AMAN"))

    def test_autentikasi_lolos(self):
        self.assertEqual(self.report.auth_results, {"spf": "pass", "dkim": "pass", "dmarc": "pass"})


class TestKetahanan(unittest.TestCase):
    def test_email_kosong_tidak_menimbulkan_kesalahan(self):
        report = analyze(b"", "kosong")
        self.assertEqual(report.urls, [])
        self.assertEqual(report.attachments, [])

    def test_email_tanpa_header_autentikasi(self):
        raw = b"From: a@example.org\r\nTo: b@example.org\r\nSubject: hai\r\n\r\nisi\r\n"
        report = analyze(raw, "minimal")
        self.assertIn("spf-missing", rules(report))
        self.assertIn("dkim-missing", rules(report))
        self.assertIn("dmarc-missing", rules(report))


if __name__ == "__main__":
    unittest.main(verbosity=2)
