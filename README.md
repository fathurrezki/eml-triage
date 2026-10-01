# eml-triage

Triase berkas `.eml` untuk analis SOC Level 1 — satu perintah untuk menjawab
pertanyaan yang selalu muncul begitu ada laporan phishing masuk:
**pengirimnya siapa sebenarnya, tautannya menuju ke mana, dan lampirannya apa.**

Tanpa dependensi (pustaka standar Python saja), tanpa koneksi keluar.
Berkas dibaca, dianalisis, selesai.

## Kenapa dibuat

Pemeriksaan awal email phishing hampir selalu berupa langkah yang sama dan
berulang: buka header, cari hasil SPF/DKIM/DMARC, bandingkan domain `From`
dengan `Reply-To`, telusuri rantai `Received` untuk mencari IP asal, lalu
kumpulkan URL dan hash lampiran untuk dimasukkan ke tiket.

Dikerjakan manual, satu email butuh beberapa menit dan gampang ada yang
terlewat saat antrean alert sedang panjang. Alat ini memadatkannya jadi satu
perintah, dengan keluaran yang sudah siap disalin ke tiket.

## Contoh keluaran

```
====================================================================
  TRIASE EMAIL  -  samples/phishing.eml
====================================================================
Subject      : [PENTING] Verifikasi ulang akun Anda dalam 24 jam
From         : Bank Example Security <security@bankexample.co.id> <no-reply@bank-example-verify[.]top>
Reply-To     : recovery[.]desk[.]2026@mail[.]example[.]ru
Return-Path  : bounce-8827@mailer-relay[.]example[.]net

-- Autentikasi -----------------------------------------------------
SPF   : fail
DKIM  : fail
DMARC : fail
Asal IP: 203[.]0[.]113[.]77   (rantai Received: 2 hop)

-- URL (3) --------------------------------------------------------
  hxxp://198[.]51[.]100[.]42/ib/verify?sid=8f21c
  hxxps://ibank[.]bankexample[.]co[.]id/verify
  hxxps://bit[.]ly/3xVerify2026

-- Lampiran (1) ---------------------------------------------------
  Formulir_Verifikasi.pdf.html  [text/html, 144 B]
    sha256: 7f84f5409eb72ad69885103371d52ce5d7930a56e004c81c78f48c38bf566a9d

-- Temuan (12) -----------------------------------------------------
  [HIGH  ] display-name-spoof
           Nama tampilan menulis security@bankexample[.]co[.]id padahal
           pengirim asli no-reply@bank-example-verify[.]top
  [HIGH  ] link-text-mismatch
           Teks tautan menulis ibank[.]bankexample[.]co[.]id tetapi
           menuju 198[.]51[.]100[.]42
  [HIGH  ] attachment-double-ext
           Ekstensi ganda menyesatkan: Formulir_Verifikasi.pdf.html
  ...

====================================================================
  VERDICT: SUSPICIOUS - eskalasi ke L2
====================================================================
```

Semua URL, domain, dan IP pada laporan ditulis **defanged**
(`hxxp://`, `[.]`) supaya aman ditempel ke tiket, chat, atau catatan insiden
tanpa risiko terklik tidak sengaja.

## Yang diperiksa

| Aturan | Tingkat | Yang dideteksi |
|---|---|---|
| `spf-fail` | high | SPF fail atau softfail |
| `dkim-fail` | high | Tanda tangan DKIM tidak sah |
| `dmarc-fail` | high | DMARC gagal |
| `display-name-spoof` | high | Nama tampilan memuat alamat email lain daripada pengirim asli |
| `url-ip-literal` | high | Tautan langsung ke alamat IP |
| `url-punycode` | high | Host punycode, indikasi serangan homograf |
| `link-text-mismatch` | high | Teks tautan menampilkan domain A, tujuannya domain B |
| `attachment-executable` | high | Lampiran `.exe`, `.js`, `.vbs`, `.lnk`, dan sejenisnya |
| `attachment-html` | high | Lampiran HTML, pola halaman login palsu offline |
| `attachment-double-ext` | high | `invoice.pdf.exe` dan variasinya |
| `attachment-macro` | high | Dokumen Office bermakro (`.docm`, `.xlsm`, `.pptm`) |
| `brand-impersonation` | high | Nama tampilan mengaku merek tertentu, domain pengirim bukan miliknya |
| `brand-in-domain` / `brand-in-url` | high | Nama merek ditanam pada domain asing: `login-microsoft.example.com` |
| `lookalike-domain` / `lookalike-url` | high | Domain tiruan satu-dua karakter: `paypa1.com`, `m1crosoft.com` |
| `html-form-external` | high | Badan email memuat formulir yang mengirim isian ke situs luar |
| `html-password-input` | high | Ada kolom kata sandi langsung di badan email |
| `html-script` | high | Badan email memuat `<script>` |
| `html-meta-refresh` | high | Pengalihan otomatis lewat `meta refresh` |
| `html-data-uri` | high | Tautan atau sumber berupa `data:` URI |
| `replyto-mismatch` | medium | Domain Reply-To berbeda dari From |
| `returnpath-mismatch` | medium | Domain Return-Path berbeda dari From |
| `spf-weak` / `dkim-missing` | medium | Hasil none, neutral, atau permerror |
| `url-shortener` | medium | Tautan disembunyikan di balik pemendek URL |
| `attachment-container` | medium | Arsip `.iso`, `.img`, `.7z`, `.rar` |
| `thread-spoof` | medium | Subjek `RE:`/`FW:` tanpa `In-Reply-To` maupun `References` |
| `messageid-missing` | medium | Tidak ada `Message-ID`, lazim pada email hasil skrip |
| `html-hidden-text` | medium | Teks disembunyikan (`font-size:0`, `display:none`) untuk mengecoh filter |
| `html-form` | medium | Formulir tanpa tujuan yang jelas |
| `url-plaintext` | low | Tautan `http://` tanpa enkripsi |
| `messageid-mismatch` | low | `Message-ID` dibuat di domain lain daripada `From` |
| `subject-lure` | low | Subjek memakai dua kata pemancing atau lebih |
| `tracking-pixel` | low | Gambar 1x1 untuk memastikan alamat aktif |
| `spf-missing` / `dmarc-missing` | low | Header autentikasi tidak ada sama sekali |

**Verdict** disusun dari temuan tersebut: satu temuan `high` langsung berarti
eskalasi, dua `medium` berarti perlu pemeriksaan lanjutan.

## Penggunaan

```bash
python eml_triage.py samples/phishing.eml
python eml_triage.py samples/                      # seluruh .eml dalam folder
python eml_triage.py samples/ --summary            # satu baris verdict per berkas
python eml_triage.py laporan.eml --iocs            # hanya daftar IOC, sudah defanged
python eml_triage.py laporan.eml --iocs --raw      # IOC apa adanya, untuk blocklist
python eml_triage.py --json laporan.eml > laporan.json
```

`--summary` berguna saat laporan phishing masuk beberapa sekaligus:

```
BERKAS                            H  M  L  VERDICT
------------------------------------------------------------------------------
credential-harvest.eml            8  3  2  SUSPICIOUS - eskalasi ke L2
legitimate.eml                    0  0  0  KEMUNGKINAN AMAN - tidak ada indikator kuat
phishing.eml                      8  3  2  SUSPICIOUS - eskalasi ke L2
```

Butuh Python 3.9 atau lebih baru. Tidak ada yang perlu dipasang.

### Untuk otomasi

`--json` mengeluarkan laporan terstruktur, dan `--fail-on-suspicious`
mengembalikan exit code 1 bila ada email yang mencurigakan — keduanya bisa
dipakai untuk menyambungkan alat ini ke pipeline atau skrip lain:

```bash
python eml_triage.py --json --fail-on-suspicious inbox/*.eml > hasil.json || echo "ada yang perlu dieskalasi"
```

## Uji

```bash
python -m unittest discover -s tests -v
```

75 uji, mencakup setiap aturan deteksi, ketiga berkas contoh, keluaran IOC dan
ringkasan, serta kasus email kosong dan email tanpa header autentikasi.

## Batasan yang perlu diketahui

- **Hasil autentikasi dibaca, bukan diverifikasi ulang.** Nilai SPF, DKIM, dan
  DMARC diambil dari header `Authentication-Results` yang ditulis mail gateway
  penerima. Kalau email diambil dari sumber yang tidak tepercaya, header itu
  sendiri bisa dipalsukan.
- **Penentuan domain terdaftar bersifat perkiraan** (dua label terakhir, dengan
  penanganan khusus untuk ccTLD bertingkat seperti `co.id`). Untuk presisi
  penuh, perlu daftar Public Suffix List.
- **Daftar merek bersifat tetap dan terbatas.** `BRANDS` di dalam
  `eml_triage.py` berisi merek yang paling sering ditiru; deteksi domain tiruan
  memakai jarak edit satu-dua karakter, jadi tiruan yang lebih kreatif
  (`micros0ft-support-id.com`) hanya tertangkap lewat aturan `brand-in-domain`.
  Sesuaikan daftarnya dengan merek dan bank yang relevan di lingkungan sendiri.
- **Tidak ada reputasi atau threat intel.** Alat ini tidak menghubungi layanan
  apa pun. URL dan hash yang dikumpulkan masih perlu dicek ke platform threat
  intelligence secara terpisah.
- **Bukan pengganti analisis mendalam.** Tujuannya mempercepat triase awal dan
  menyeragamkan catatan, bukan memutuskan akhir.

## Catatan data

Ketiga berkas di `samples/` **dibuat sendiri untuk keperluan uji**. Seluruh
domain memakai rentang dokumentasi RFC 2606 (`example.org`, `example.net`) dan
IP memakai rentang RFC 5737 (`198.51.100.0/24`, `203.0.113.0/24`).

Tidak ada data nyata, tidak ada email pelanggan, dan tidak ada indikator dari
lingkungan produksi mana pun di repositori ini.
