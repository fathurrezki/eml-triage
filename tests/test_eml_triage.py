"""Uji unit untuk eml-triage. Jalankan: python -m unittest discover -s tests"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eml_triage import (  # noqa: E402
    Attachment,
    Finding,
    Report,
    analyze,
    brands_in,
    canonical,
    check_attachments,
    check_brand,
    check_headers,
    check_html_body,
    check_urls,
    collect_iocs,
    decide,
    defang,
    edit_distance,
    expand_paths,
    extension_of,
    host_of,
    is_private_ip,
    lookalike_of,
    main,
    registrable,
    render_iocs,
    render_summary,
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


# ==========================================================================
# v1.1 - penyamaran merek, isi HTML, header, dan keluaran IOC
# ==========================================================================

class TestUtilitasMerek(unittest.TestCase):
    def test_canonical_mengembalikan_huruf_dari_tiruan_angka(self):
        self.assertEqual(canonical("M1cr0s0ft"), canonical("Microsoft"))
        self.assertEqual(canonical("Pay-Pa1"), canonical("paypal"))
        self.assertNotEqual(canonical("Micro Focus"), canonical("Microsoft"))

    def test_edit_distance_berhenti_di_cap(self):
        self.assertEqual(edit_distance("paypal.com", "paypa1.com"), 1)
        self.assertEqual(edit_distance("abc", "xyz", cap=1), 2)

    def test_brands_in_menangkap_nama_tampilan(self):
        self.assertEqual(brands_in("Microsoft 365 Security"), ["microsoft"])

    def test_brands_in_pendek_harus_kata_utuh(self):
        self.assertEqual(brands_in("fabrication hybrid"), [])
        self.assertEqual(brands_in("Info BCA"), ["bca"])

    def test_lookalike_hanya_untuk_domain_tiruan(self):
        self.assertEqual(lookalike_of("paypal.com"), ("", 0))
        legit, distance = lookalike_of("paypa1.com")
        self.assertEqual(legit, "paypal.com")
        self.assertEqual(distance, 1)

    def test_domain_sah_lain_tidak_dianggap_tiruan(self):
        self.assertEqual(lookalike_of("bni.co.id"), ("", 0))


def build(**kwargs):
    """Report minimal untuk menguji satu aturan saja."""
    base = dict(source="uji", from_address="no-reply@example.net")
    base.update(kwargs)
    return Report(**base)


class TestPenyamaranMerek(unittest.TestCase):
    def test_nama_tampilan_mengaku_merek(self):
        report = build(from_display="Microsoft 365 Security")
        self.assertEqual({f.rule for f in check_brand(report)}, {"brand-impersonation"})

    def test_merek_dengan_domain_sahnya_tidak_dilaporkan(self):
        report = build(from_display="Microsoft 365", from_address="no-reply@microsoft.com")
        self.assertEqual(check_brand(report), [])

    def test_nama_merek_ditanam_di_domain_pengirim(self):
        report = build(from_address="billing@paypal-secure.example.com")
        self.assertIn("brand-in-domain", {f.rule for f in check_brand(report)})

    def test_domain_pengirim_tiruan(self):
        report = build(from_address="service@paypa1.com")
        self.assertIn("lookalike-domain", {f.rule for f in check_brand(report)})

    def test_nama_merek_pada_host_tautan(self):
        report = build(urls=["https://login-microsoft.example.com/auth"])
        self.assertIn("brand-in-url", {f.rule for f in check_brand(report)})

    def test_host_tautan_sah_tidak_dilaporkan(self):
        report = build(urls=["https://login.microsoftonline.com/common"])
        self.assertEqual(check_brand(report), [])

    def test_tanpa_alamat_pengirim_tidak_error(self):
        self.assertEqual(check_brand(build(from_address="")), [])


class TestIsiHtml(unittest.TestCase):
    def test_formulir_mengirim_ke_luar(self):
        html = '<form action="https://evil.example.com/post"><input name="a"></form>'
        self.assertIn("html-form-external", {f.rule for f in check_html_body(html)})

    def test_formulir_tanpa_tujuan(self):
        self.assertIn("html-form", {f.rule for f in check_html_body("<form><input></form>")})

    def test_kolom_kata_sandi(self):
        self.assertIn("html-password-input", {f.rule for f in check_html_body('<input type="password">')})

    def test_skrip_di_badan_email(self):
        self.assertIn("html-script", {f.rule for f in check_html_body("<script>alert(1)</script>")})

    def test_pengalihan_meta_refresh(self):
        html = '<meta http-equiv="refresh" content="0;url=https://evil.example.com">'
        self.assertIn("html-meta-refresh", {f.rule for f in check_html_body(html)})

    def test_data_uri_pada_tautan(self):
        html = '<a href="data:text/html;base64,PGh0bWw+PC9odG1sPg==">buka</a>'
        self.assertIn("html-data-uri", {f.rule for f in check_html_body(html)})

    def test_teks_tersembunyi(self):
        html = '<div style="font-size:0px">kata pengecoh filter</div>'
        self.assertIn("html-hidden-text", {f.rule for f in check_html_body(html)})

    def test_piksel_pelacak(self):
        html = '<img src="https://t.example.com/o.gif" width="1" height="1">'
        self.assertIn("tracking-pixel", {f.rule for f in check_html_body(html)})

    def test_gambar_normal_bukan_piksel_pelacak(self):
        html = '<img src="https://t.example.com/logo.png" width="320" height="80">'
        self.assertEqual(check_html_body(html), [])

    def test_html_kosong_aman(self):
        self.assertEqual(check_html_body(""), [])


class TestHeaderTambahan(unittest.TestCase):
    def test_subjek_balasan_tanpa_rantai(self):
        report = build(subject="RE: Tagihan bulan ini", message_id="<a@example.net>")
        self.assertIn("thread-spoof", {f.rule for f in check_headers(report)})

    def test_balasan_dengan_in_reply_to_tidak_dilaporkan(self):
        report = build(subject="Re: Tagihan", message_id="<a@example.net>", in_reply_to="<b@example.net>")
        self.assertNotIn("thread-spoof", {f.rule for f in check_headers(report)})

    def test_message_id_hilang(self):
        self.assertIn("messageid-missing", {f.rule for f in check_headers(build(subject="Halo"))})

    def test_message_id_beda_domain(self):
        report = build(subject="Halo", message_id="<99@relay.example.org>")
        self.assertIn("messageid-mismatch", {f.rule for f in check_headers(report)})

    def test_subjek_pemancing_butuh_dua_kata(self):
        satu = build(subject="Verifikasi data karyawan", message_id="<a@example.net>")
        self.assertNotIn("subject-lure", {f.rule for f in check_headers(satu)})
        dua = build(subject="Verifikasi akun Anda segera", message_id="<a@example.net>")
        self.assertIn("subject-lure", {f.rule for f in check_headers(dua)})


class TestLampiranMakro(unittest.TestCase):
    def test_dokumen_bermakro(self):
        item = Attachment("Tagihan.xlsm", "application/vnd.ms-excel.sheet.macroEnabled.12", 10, "a" * 64)
        self.assertEqual([f.rule for f in check_attachments([item])], ["attachment-macro"])

    def test_dokumen_biasa_aman(self):
        item = Attachment("Tagihan.xlsx", "application/vnd.ms-excel", 10, "a" * 64)
        self.assertEqual(check_attachments([item]), [])


class TestIOC(unittest.TestCase):
    def setUp(self):
        self.report = analyze(read_sample("phishing.eml"), "phishing.eml")

    def test_ip_url_dan_ip_asal_terkumpul(self):
        self.assertIn("198.51.100.42", self.report.iocs["ips"])
        self.assertIn("203.0.113.77", self.report.iocs["ips"])

    def test_hash_lampiran_masuk_ioc(self):
        self.assertEqual(len(self.report.iocs["sha256"]), 1)

    def test_domain_pengirim_masuk_ioc(self):
        self.assertIn("bank-example-verify.top", self.report.iocs["domains"])

    def test_render_ioc_defang_kecuali_raw(self):
        teks = render_iocs([self.report])
        self.assertIn("hxxp://198[.]51[.]100[.]42/ib/verify?sid=8f21c", teks)
        mentah = render_iocs([self.report], raw=True)
        self.assertIn("http://198.51.100.42/ib/verify?sid=8f21c", mentah)

    def test_sha256_tidak_ikut_didefang(self):
        self.assertIn(self.report.attachments[0].sha256, render_iocs([self.report]))


class TestSampelPanenKredensial(unittest.TestCase):
    def setUp(self):
        self.report = analyze(read_sample("credential-harvest.eml"), "credential-harvest.eml")

    def test_verdict_eskalasi(self):
        self.assertTrue(self.report.verdict.startswith("SUSPICIOUS"))

    def test_aturan_baru_ikut_terpicu(self):
        wajib = {
            "brand-impersonation",
            "brand-in-url",
            "html-form-external",
            "html-password-input",
            "html-script",
            "html-hidden-text",
            "tracking-pixel",
            "thread-spoof",
            "attachment-macro",
            "subject-lure",
        }
        self.assertTrue(wajib.issubset(rules(self.report)), wajib - rules(self.report))

    def test_temuan_tidak_kembar(self):
        kunci = [(f.severity, f.rule, f.detail) for f in self.report.findings]
        self.assertEqual(len(kunci), len(set(kunci)))


class TestKeluaranBerkasBanyak(unittest.TestCase):
    def test_folder_diperluas_menjadi_daftar_eml(self):
        berkas = expand_paths([SAMPLES])
        self.assertTrue(all(b.lower().endswith(".eml") for b in berkas))
        self.assertGreaterEqual(len(berkas), 3)

    def test_berkas_biasa_dilewatkan_apa_adanya(self):
        self.assertEqual(expand_paths(["a.eml", "b.eml"]), ["a.eml", "b.eml"])

    def test_ringkasan_memuat_satu_baris_per_berkas(self):
        laporan = [analyze(read_sample(n), n) for n in ("legitimate.eml", "phishing.eml")]
        teks = render_summary(laporan)
        self.assertIn("legitimate.eml", teks)
        self.assertIn("phishing.eml", teks)
        self.assertEqual(len(teks.splitlines()), 4)      # judul + garis + 2 berkas

    def test_exit_code_1_saat_mencurigakan(self):
        import contextlib
        import io

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            kode = main([os.path.join(SAMPLES, "phishing.eml"), "--summary", "--fail-on-suspicious"])
        self.assertEqual(kode, 1)
        self.assertIn("SUSPICIOUS", buffer.getvalue())

    def test_exit_code_0_untuk_email_aman(self):
        import contextlib
        import io

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            kode = main([os.path.join(SAMPLES, "legitimate.eml"), "--iocs", "--fail-on-suspicious"])
        self.assertEqual(kode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
