<div align="center">

[English](../../README.md) · [简体中文](README_zh.md) · [繁體中文](README_zh-TW.md) · [日本語](README_ja.md) · [한국어](README_ko.md) · [Türkçe](README_tr.md) · [Русский](README_ru.md) · [Tiếng Việt](README_vi.md) · [ไทย](README_th.md) · [Deutsch](README_de.md) · [Español](README_es.md) · [Français](README_fr.md) · [Українська](README_uk.md) · [Polski](README_pl.md) · [Português (Brasil)](README_pt-BR.md) · [العربية](README_ar.md) · [فارسی](README_fa.md) · **Bahasa Indonesia** · [Italiano](README_it.md)
· [Ελληνικά](README_el.md) · [മലയാളം](README_ml.md) · [Roman Urdu](README_ur-Latn.md) · [Română](README_ro.md)

# REA: Rekayasa Balik Apa Pun

### Satu MCP untuk rekayasa balik pada berbagai biner, aplikasi, dan perilaku saat runtime.

**Melihat fitur yang Anda sukai. Pahami cara kerjanya hingga ke tingkat biner.**

[![npm version](https://img.shields.io/npm/v/rea-agents?style=flat-square&color=cb3837)](https://www.npmjs.com/package/rea-agents)
[![MCP tool catalog](https://img.shields.io/badge/MCP-tool_catalog-5c4ee5?style=flat-square)](../mcp-contracts.md#generated-catalog)
[![Node.js requirements](https://img.shields.io/badge/Node.js-requirements-339933?style=flat-square&logo=nodedotjs&logoColor=white)](#current-status)
[![skills.sh](https://skills.sh/b/morluto/rea?style=flat-square)](https://skills.sh/morluto/rea/reverse-engineer-anything)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](../../LICENSE)
[![Discord](https://img.shields.io/discord/1556595354999332884?logo=discord&logoColor=white&label=Discord&color=5865F2)](https://discord.gg/GkcryMnJDM)

<a href="https://trendshift.io/repositories/82054?utm_source=repository-badge&amp;utm_medium=badge&amp;utm_campaign=badge-repository-82054" target="_blank" rel="noopener noreferrer"><img src="https://trendshift.io/api/badge/repositories/82054" alt="morluto%2Frea | Trendshift" width="250" height="55"/></a>

**[Situs Web](https://rea.tools/id/) · [Panduan](https://rea.tools/id/guides/) · [Contoh Penggunaan](https://rea.tools/id/showcase/)**

[Mulai Cepat](#mulai-cepat) · [Cara Kerja REA](#cara-kerja-rea) · [Hal yang Dapat Anda Analisis](#hal-yang-dapat-anda-analisis) · [Contoh Penggunaan](#contoh-penggunaan) · [FAQ](#faq) · [Alat GNU objdump dan Rizin](../reverse-engineering-tools.md) · [Dokumentasi](#dokumentasi)

<code>npx rea-agents setup</code>

</div>

> [!IMPORTANT]
> Sumber resmi REA: [morluto/rea](https://github.com/morluto/rea), [rea.tools](https://rea.tools/), [rea-agents](https://www.npmjs.com/package/rea-agents) (npm).
> Gunakan tautan instalasi dan rilis dari sumber resmi ini. Nama repositori yang mirip atau README yang disalin tidak membuktikan bahwa unduhan tersebut resmi.

<div align="center">

<br />

<img src="../assets/rea-hopper-analysis.png" alt="REA menjalankan jembatan analisisnya di dalam Hopper saat memeriksa biner native" width="1200" />

<br /><br />

<table aria-label="Komunitas REA">
<tr>
<td align="center" width="360">
  <a href="https://discord.gg/GkcryMnJDM">
    <img src="../assets/discord.svg" height="42" alt="Discord" /><br />
    <strong>Bergabunglah dengan Komunitas Rekayasa Balik</strong>
  </a><br />
  <sub>Discord · Tanya Jawab · Berbagi Hasil</sub>
</td>
</tr>
</table>

<br />

</div>

---

Melihat fitur dalam suatu aplikasi yang ingin Anda hadirkan di produk sendiri? Minta agen Anda menyelidikinya menggunakan REA. REA dapat memeriksa aplikasi tanpa kode sumbernya, menjelaskan cara kerja fitur tersebut, menunjukkan bukti, dan membangun versi untuk proyek Anda.

REA menghubungkan agen Anda dengan berbagai alat untuk memeriksa biner native, aplikasi JavaScript dan Electron, assembly .NET, serta situs web. Anda juga dapat menggunakan alat yang sama dari terminal. Analisis dijalankan secara lokal, dan hasilnya mencakup bukti serta keterbatasan yang mendasari setiap kesimpulan.

Proses penyiapan mendaftarkan REA ke agen Anda dan memasang instruksi alur kerja yang sesuai. Analisis native dapat menggunakan instalasi Hopper, Ghidra, atau IDA yang sudah ada. Proses penyiapan juga dapat memasang Hopper secara opsional setelah mendapatkan persetujuan. Analisis JavaScript statis tidak memerlukan mesin analisis native.

> **[Kunjungi situs web REA](https://rea.tools/id/)** untuk mendapatkan petunjuk penyiapan, panduan bergambar, dan studi kasus nyata.

## Mulai Cepat

Di Linux, peluncuran Ghidra, JADX dan alat firmware serta analisis statis JavaScript/Electron memerlukan `ps` yang kompatibel dengan procps pada `PATH` REA untuk memeriksa kepemilikan proses. Lihat prasyarat Linux.

### Siapkan agen Anda

Dengan Node.js dan npm yang telah terpasang, jalankan:

```bash
npx rea-agents setup
```

Pilih agen yang ingin digunakan, tinjau perubahan yang diusulkan, lalu setujui perubahan tersebut. Proses penyiapan menambahkan server MCP REA dan instruksi alur kerja yang sesuai, serta membuat cadangan konfigurasi yang sudah ada. Setelah itu, mulai ulang agen Anda.

Penyiapan mendukung Claude Code, Codex, Cursor, Gemini CLI, Grok Build, dan [agen lainnya](../installation.md#supported-agents). Lihat [instalasi dan penyiapan](../installation.md) untuk konfigurasi penyedia dan pendaftaran MCP secara manual.

MCP menggunakan skema input ringkas secara default. Untuk petunjuk bidang lengkap dan validasi bertingkat, atur `REA_MCP_INPUT_SCHEMA_PROFILE=full` pada pendaftaran MCP. Kedua profil mempertahankan semua alat dan validasi server kanonis yang sama; lihat panduan kontrak MCP.

### Minta agen Anda

```text
Pahami cara kerja pencarian di aplikasi Notes, tunjukkan buktinya, dan buat fitur serupa untuk proyek saya.
```

Ganti Notes dengan aplikasi target dan fitur yang ingin Anda pahami.

### Gunakan terminal

Periksa direktori aplikasi JavaScript/Electron yang telah diekstrak atau berkas ASAR:

```bash
npx -y rea-agents@latest analyze-javascript-application /absolute/path/to/app --json
```

Hasilnya mencakup modul, impor, batas antarkomponen Electron, dan bukti yang mendasarinya. Ganti jalur tersebut dengan lokasi target Anda, misalnya `"D:/apps/example"` di Windows.

Untuk memasang perintah `rea` agar dapat digunakan secara rutin:

```bash
npm install --global rea-agents
rea --help
```

Untuk analisis native, konfigurasikan penyedia terlebih dahulu. Lihat [Panduan CLI dan Bukti](../cli.md) untuk perintah native, pemilihan penyedia, snapshot, dan pembuatan skrip.

### Perbarui REA

REA berkembang dengan cepat, dan rilis baru sering menyertakan perbaikan bug. Pastikan instalasi Anda selalu diperbarui.

Untuk CLI yang dipasang melalui `npm install --global` atau `bun add --global`:

```bash
rea update
```

`rea --update` adalah alias `rea update` dengan opsi keluaran global yang sama. Perintah pembaruan menyimpan stdout/stderr gabungan maksimal 4 MiB. Metadata terlalu besar ditolak setelah perintah selesai; instalasi verbose menyimpan diagnostik terbatas. Kemajuan mengikuti backpressure terminal dan menunggu penulisan yang telah dikirim.

Pembaruan global dengan Bun memerlukan Bun 1.2.17 atau yang lebih baru. Pada rilis Bun yang lebih lama, perbarui Bun secara manual sebelum menjalankan `rea update`.

Untuk memperbarui pendaftaran agen dan skill Anda, jalankan perintah penyiapan yang ditampilkan oleh proses pembaruan.

Jika Anda menggunakan `npx`, perbarui penyiapan agen dengan:

```bash
npx rea-agents@latest setup
```

Tinjau perubahan penyiapan dan mulai ulang agen Anda. Untuk menjalankan perintah CLI sekali pakai, gunakan `npx rea-agents@latest` diikuti dengan perintah yang diinginkan. Dengan Bun, gunakan `bunx rea-agents@latest` sebagai pengganti `npx rea-agents@latest`.

## Cara Kerja REA

Agen Anda memanggil REA melalui MCP untuk memeriksa target dan menelusuri kode yang relevan. REA mengembalikan temuan beserta bukti pendukungnya. Agen kemudian menggunakan temuan tersebut untuk mengajukan pertanyaan lanjutan, menjelaskan perilaku, atau menulis dan menguji implementasi.

Perintah CLI menggunakan alur kerja yang sama.

![Alur investigasi REA: agen Anda menanyakan sesuatu tentang target lokal, REA memeriksa dan menelusurinya menggunakan alat analisis, lalu agen menggunakan kode, referensi, dan hal-hal yang belum diketahui dari hasil tersebut untuk menjelaskan, mengimplementasikan, dan menguji.](../../website/public/assets/figures/rea-investigation-flow.svg)

[Buka ilustrasi dalam ukuran penuh](../../website/public/assets/figures/rea-investigation-flow.svg).

<a id="current-status"></a>

## Hal yang Dapat Anda Analisis

REA memerlukan Node.js 22.x (>=22.23.4), 24.x (>=24.22.1), atau 26+ (>=26.12.1), beserta npm.

Alat tambahan dan dukungan sistem host bergantung pada target yang dianalisis:

| Target                     | Hasil yang diberikan REA                                                                                           | Persyaratan dan panduan                                                                                                                               |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| Biner native               | Pseudocode, assembly, string, simbol, pemanggilan, dan referensi                                                   | Hopper, Ghidra, atau IDA; [analisis native](../native-investigation.md)                                                                               |
| Tata letak ELF offline     | Bagian, segmen, simbol/relokasi asli, dan kandidat mitigasi statis                                                 | pwntools yang disediakan pemanggil pada Linux x64; [diagnostik biner](../binary-diagnostics.md)                                                       |
| PE certificates            | Authenticode WIN_CERTIFICATE entries and PKCS#7 signer/X.509 identity fields                                       | Built-in static PE inspection; [PE certificates](../pe-certificates.md)                                                                               |
| PE imports                 | Import and delay-load DLL names, ordinals, IAT RVAs and pefile import hash                                         | Built-in static PE inspection; [PE imports](../pe-imports.md)                                                                                         |
| Artefak WASM               | Validasi, bagian, bentuk WAT import/ekspor yang tepat, dan WAT yang didekode                                       | WABT 1.0.42 yang disediakan pemanggil; `inspect_wasm_artifact`                                                                                        |
| Bytecode EVM               | Selector dispatch, offset byte, argumen yang disimpulkan, dan sifat mutabilitas                                    | Pembawa data raw/hex lokal; [panduan EVM offline](../evm-bytecode.md)                                                                                 |
| Rust binaries              | Embedded cargo-auditable dependency list                                                                           | [Rust binaries](../rust-binaries.md)                                                                                                                  |
| ELF notes                  | PT_NOTE/SHT_NOTE owners, types, GNU build-id and ABI-tag fields                                                    | Built-in static ELF inspection; [ELF notes](../elf-notes.md)                                                                                          |
| Apple IPS crashes          | .ips metadata, threads, images, registers and crash classes                                                        | Built-in static JSON inspection; [Apple IPS](../apple-ips.md)                                                                                         |
| Linux kernel modules       | .modinfo keys, __versions CRCs, this_module presence, and signature trailer                                        | Built-in static ELF inspection; [kernel modules](../kernel-modules.md)                                                                                |
| Erlang BEAM                | IFF chunks, atoms, exports, and tables                                                                             | Built-in static BEAM inspection; [Erlang BEAM](../erlang-beam.md)                                                                                     |
| Crash Linux yang direkam   | Catatan mentah, register/sinyal setiap thread yang direkam, dan kandidat pemetaan opsional                         | pwntools yang disediakan pemanggil; GDB/pwndbg opsional; [crash yang direkam](../recorded-crashes.md)                                                 |
| Instalasi desktop          | Kandidat runtime, berkas pendukung, penanda komponen, dan langkah berikutnya                                       | Pemeriksaan direktori dan header terbatas；[Aplikasi desktop](../desktop-applications.md)                                                             |
| JavaScript / Electron      | Modul, impor, source map, rute, IPC, dan hubungan add-on native                                                    | Node.js dan npm; [analisis aplikasi](../javascript-application-workflows.md); Linux: procps `ps`                                                      |
| Situs web                  | Struktur halaman, skrip, pengamatan jaringan, dan tangkapan layar yang diminta                                     | Peramban berbasis Chrome; [analisis peramban](../browser-observation.md)                                                                              |
| Rekaman jaringan tersimpan | Permintaan, respons, payload yang terekspos, dan lokasi sumber                                                     | HAR / Fiddler Everywhere SAZ; mitmdump di Linux untuk rekaman native mitmproxy; [panduan rekaman](../web-network-captures.md)                         |
| Capturan paket             | Endpoint, DNS, TLS SNI, distribusi protokol, dan permintaan HTTP                                                   | tshark dan capinfos buatan pemanggil; [panduan pcap](../pcap-analysis.md)                                                                             |
| Assembly .NET              | Metadata, instruksi CIL, dependensi native yang dideklarasikan, dan perbandingan build                             | Tidak ada (hanya analisis statis); [panduan kode terkelola](../managed-code-analysis.md)                                                              |
| PyInstaller                | CArchive, PYZ, Python bytecode                                                                                     | Static inspection; [Python packaged applications](../python-packaged-applications.md)                                                                 |
| APK Android                | Deklarasi manifest, kelas, metode hasil dekompilasi, dan referensi                                                 | JADX mode headless dan JDK lengkap di Linux/macOS/Windows x64; [panduan Android](../android-analysis.md)                                              |
| Perangkat Android          | Perangkat, paket, proses, log, dump, tangkapan layar, serta transfer APK/berkas                                    | adb buatan pemanggil (emulator atau perangkat); [panduan ADB](../adb-device-analysis.md)                                                              |
| iOS devices                | Devices, lockdown info, bounded syslog slices, screen captures, crash reports and installed-app provisioning facts | Caller-supplied `pymobiledevice3` launcher on macOS (lane not maintainer-verified; REA never installs it); [iOS device plane](../idevice-provider.md) |
| Proyek JEB                 | Unit proyek bertenaga mesin, hash artefak, dan pseudokode tipe/metode                                              | Klien JEB yang dijalankan pemanggil dan menyajikan MCP, dipilih dengan REA_JEB_MCP_URL; [panduan JEB](../jeb-analysis.md)                             |
| Resource Android           | Manifest terdekode, tabel string, lokal, dan fakta versi                                                           | Peluncur Apktool buatan pemanggil; [panduan resource](../apktool-resource-analysis.md)                                                                |
| Aplikasi Flutter           | Hash snapshot Dart, hash pustaka per ABI, dan asal build engine                                                    | Tidak ada (parsing APK statis); [panduan Flutter](../flutter-analysis.md)                                                                             |
| Firmware                   | Wilayah, hasil ekstraksi, dan pengalihan ke analisis native                                                        | Binwalk / Unblob di Linux; [panduan firmware](../firmware-analysis.md)                                                                                |
| Paket rekaman              | Kolom terpilih, nilai berulang, filter, dan aturan decode-as                                                       | Linux: TShark 4.x + prlimit; [panduan tangkapan](../packet-captures.md)                                                                               |
| Browser extension packages | CRX3/XPI headers, manifest surfaces, JAR digest facts and signature-artifact presence                              | Built-in static ZIP inspection on Linux/macOS/Windows; signatures are not verified; [container inspections](../containers.md)                         |
| PyInstaller executables    | CArchive cookie, TOC entries, embedded PYZ module inventories and pyc header facts                                 | Built-in static byte inspection on Linux/macOS/Windows; entry contents are never executed or extracted; [container inspections](../containers.md)     |
| Sinyal logika terekam      | Anotasi dekoder, rentang sampel, dan diagnostik                                                                    | Linux: sigrok-cli 0.7.2 + prlimit; [panduan sinyal](../signal-recordings.md)                                                                          |
| Paket dan sumber daya      | Inventaris berkas, digest, plist, struktur paket Apple, dan sumber daya yang diekstrak                             | [Panduan artefak dan JavaScript](../javascript-artifact-reconstruction.md), [aplikasi Apple](../apple-application-analysis.md)                        |
| Perilaku proses            | Keluaran terminal, interaksi, pengamatan proses keluar dan sistem berkas, serta perbandingan eksekusi              | Linux/macOS dengan PTY native; [perekaman proses](../process-capture.md)                                                                              |
| Biner Go                   | Versi compiler tertanam, modul, penggantian dan pengaturan build                                                   | Pemeriksaan statis bawaan ELF/PE/thin Mach-O; Tidak perlu memasang Go                                                                                 |
| Database SQLite            | Tabel, kolom, indeks, view, trigger dan baris terpilih dari tabel biasa                                            | Snapshot database/WAL lokal; Node.js 24.x >=24.15 atau 26+ dengan batas SQLite native                                                                 |
| Objek kode GPU             | Target CUDA/HIP, parameter dan sumber daya kernel terpilih, teks PTX yang dipertahankan                            | Pemeriksaan statis bawaan ELF/PE/fatbin/CUBIN/PTX; [GPU](../gpu-code-objects.md)                                                                      |
| Berkas model               | Metadata GGUF / safetensors, deklarasi tensor dan total turunan                                                    | Pemeriksaan header; hash seluruh berkas opsional; [GGUF / safetensors](../model-artifacts.md)                                                         |
| Metadata IL2CPP            | Citra assembly Unity global-metadata.dat, nama tipe/metode dan rentang indeks                                      | Dekode statis versi 24, 27, 29, 31, 39; tanpa Unity                                                                                                   |
| Godot PCK                  | Inventaris dan ekstraksi arsip, header/direktori asli dan identitas konten terpilih                                | Format statis 2, 3, 4; tanpa Godot                                                                                                                    |
| Tanda tangan APK           | Penanda tangan v1/v2/v3/v3.1, sidik jari sertifikat, rotasi kunci dan konsistensi internal digest                  | Pemeriksaan statis bawaan; `inspect_apk_signature`                                                                                                    |

Pemeriksaan JavaScript dan .NET statis membaca berkas yang disediakan tanpa menjalankan aplikasinya. Perekaman runtime menjalankan atau berinteraksi dengan target yang dipilih menggunakan izin pengguna Anda. Setiap panduan runtime menjelaskan dampaknya.

<a id="choosing-a-deep-analysis-provider"></a>

Format native dan dukungan sistem host berbeda-beda menurut penyedia. Lihat [penyiapan Hopper dan Ghidra](../installation.md#hopper), [panduan IDA](../ida-provider.md), [Kuna](../kuna-provider.md), dan [dukungan eksperimental Ghidra di Windows](../windows-ghidra-p0.md).

Ghidra juga mendukung [analisis DOS 16-bit](../ghidra-dos.md).

Untuk biner berukuran besar, tingkatkan batas waktu startup menggunakan `REA_GHIDRA_STARTUP_TIMEOUT_MS` / `REA_HOPPER_STARTUP_TIMEOUT_MS`.

Untuk memilih penyedia, lihat [panduan CLI](../cli.md#choose-a-provider).

Periksa [ketersediaan rilis](../installation.md#released-package-and-main) untuk mengetahui fitur yang ditambahkan setelah rilis npm terbaru.

## Contoh Penggunaan

<a href="https://rea.tools/id/showcase/">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../assets/rea-showcases-dark.svg" />
    <img alt="Ilustrasi contoh penggunaan DX-Ball sound-pan, Notion clipboard-bridge, dan TH04 bullet-ring" src="../assets/rea-showcases.svg" />
  </picture>
</a>

### DX-Ball: merekonstruksi perhitungan sound-pan

Ikuti pemanggilan suara hingga ke fungsi pembantu yang mengubah posisi menjadi nilai pan, periksa instruksinya, lalu ubah pseudocode yang belum lengkap menjadi C. Hasil rekonstruksi tersebut lolos pada 3.205 kasus x86 asli dan mereproduksi seluruh 63 byte fungsi hasil kompilasi.

[Baca studi kasus](https://rea.tools/id/showcase/dx-ball/) · [Repositori rekonstruksi](https://github.com/N0zoM1z0/dx-ball)

### Notion: menelusuri jembatan clipboard Electron

Temukan API clipboard pada renderer, telusuri jalurnya melalui preload dan IPC hingga ke proses utama, lalu periksa format clipboard kaya.

[Baca studi kasus](https://rea.tools/id/showcase/notion/)

### TH04: memulihkan perhitungan bullet-ring DOS

Periksa instruksi 16-bit dari gim PC-98 asli, pulihkan perhitungan sudut tetap dan sudut yang diarahkan, lalu bandingkan C++ hasil rekonstruksi dengan keluaran historis kompiler.

[Baca studi kasus](https://rea.tools/id/showcase/th04/) · [Repositori rekonstruksi](https://github.com/N0zoM1z0/th04)

Jika Anda telah menggunakan REA untuk menganalisis sesuatu yang menarik, kami ingin melihat hasilnya. Bagikan kasus Anda melalui [issue](https://github.com/morluto/rea/issues) atau [pull request](https://github.com/morluto/rea/pulls), sertakan target, pertanyaan Anda, bagaimana REA membantu, dan apa yang Anda temukan.

## FAQ

<details>
<summary><strong>Agen apa saja yang dapat menggunakan REA?</strong></summary>

Agen apa pun yang mendukung server MCP lokal dapat menggunakan REA. Proses penyiapan mengonfigurasi [agen yang didukung](../installation.md#supported-agents). Klien lain dapat menggunakan [pendaftaran MCP manual](../installation.md#mcp-registry).

</details>

<details>
<summary><strong>Apakah saya memerlukan Hopper, Ghidra, atau IDA?</strong></summary>

Analisis native mendalam menggunakan salah satu dari ketiganya. Pemeriksaan JavaScript dan .NET statis dapat dilakukan tanpa mesin analisis native.

Proses penyiapan dapat memasang Hopper setelah memperoleh persetujuan. Ghidra dan IDA menggunakan instalasi yang sudah tersedia. Lihat [penyiapan penyedia](../installation.md#hopper).

</details>

<details>
<summary><strong>Apakah saya harus menjalankan Hopper terlebih dahulu?</strong></summary>

REA akan menjalankan Hopper saat suatu operasi membutuhkannya. Di macOS, dialog saat pertama kali dijalankan mungkin meminta Anda memilih mode demo atau mengaktifkan lisensi.

Lihat [startup dan pemecahan masalah Hopper](../installation.md#launcher-paths-and-troubleshooting).

</details>

<details>
<summary><strong>Apa fungsi memasang skill dari skills.sh?</strong></summary>

Skill tersebut menyediakan instruksi investigasi untuk agen Anda. Gunakan `npx rea-agents setup` untuk mendaftarkan server MCP REA dan memasang instruksi yang sesuai, lalu mulai ulang agen Anda.

Lihat [instalasi khusus skill](../installation.md#skill-only-installation).

</details>

<details>
<summary><strong>Kode seperti apa yang dihasilkan REA?</strong></summary>

Analisis native menghasilkan pseudocode dan assembly. Analisis JavaScript/Electron memulihkan modul dan hubungan antarmodulnya. Agen Anda menggunakan temuan tersebut untuk menulis dan menguji implementasi. [Contoh penggunaan](#contoh-penggunaan) menyediakan contoh yang telah dikerjakan.

</details>

<details>
<summary><strong>Apakah REA mengunggah aplikasi saya?</strong></summary>

REA menganalisis target secara lokal. Agen Anda menerima hasil alat, sedangkan penyedia model yang digunakannya memiliki kebijakan datanya sendiri.

</details>

<details>
<summary><strong>Apa yang harus saya lakukan jika menemukan bug?</strong></summary>

Perbarui terlebih dahulu. Rilis terbaru mungkin sudah memperbaiki masalah tersebut.

Untuk CLI yang dipasang melalui `npm install --global` atau `bun add --global`:

```bash
rea update
```

Untuk penyiapan agen melalui `npx`:

```bash
npx rea-agents@latest setup
```

Jika Anda menggunakan agen, selesaikan [pembaruan penyiapan](#perbarui-rea) dan mulai ulang agen tersebut.

Coba kembali tugas yang sama. Jika masalah masih terjadi, [buat issue](https://github.com/morluto/rea/issues) dengan menyertakan versi REA, jenis target, langkah-langkah untuk mereproduksi masalah, dan keluaran kesalahan.

</details>

## Dokumentasi

Mulailah dengan [panduan praktik di situs web](https://rea.tools/id/guides/).

Untuk mengetahui opsi, prasyarat, dan kontrak hasil secara tepat:

- [Instalasi dan penyiapan](../installation.md): pendaftaran agen, konfigurasi penyedia, pembaruan, dan penghapusan instalasi.
- [Kesiapan dan pemecahan masalah](../installation.md#check-readiness-for-your-task): mendiagnosis satu agen atau mesin analisis.
- [CLI dan Bukti](../cli.md): perintah, pemilihan penyedia, snapshot, impor/ekspor, dan status keluar.
- [Kontrak MCP](../mcp-contracts.md) dan [prompt agen](../mcp-prompts.md): hasil alat, sesi, dan investigasi terpandu.
- [Katalog alat](../mcp-contracts.md#generated-catalog): inventaris alat, penyedia, dan perintah CLI yang dibuat secara otomatis.
- [Peta jalan](../roadmap.md): pekerjaan yang direncanakan dan pelacak kemampuan.

Laporkan kerentanan melalui [SECURITY.md](../../SECURITY.md).

## Riwayat Bintang

🎉 **300.000 bintang GitHub, terima kasih!**

Terima kasih kepada semua orang yang menggunakan REA, melaporkan bug, meminta fitur, menguji build, dan berkontribusi dalam perbaikan.

<a href="https://www.star-history.com/?repos=morluto%2Frea&amp;type=date">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=morluto/rea&amp;type=date&amp;theme=dark&amp;legend=top-left" />
    <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=morluto/rea&amp;type=date" />
    <img alt="Riwayat bintang GitHub REA" src="https://api.star-history.com/chart?repos=morluto/rea&amp;type=date" />
  </picture>
</a>

## Penafian

Lihat [DISCLAIMER.md](../../DISCLAIMER.md) untuk panduan penggunaan yang bertanggung jawab.

REA ditujukan untuk penelitian, pendidikan, interoperabilitas, pelestarian perangkat lunak, dan analisis perangkat lunak yang Anda miliki atau diizinkan untuk Anda periksa, sesuai hukum.

The project's position on illegal or unauthorized use covers all REA
versions, distribution channels, and platforms; each copy retains its
applicable licenses.

## Kontribusi

Kami sangat menghargai bantuan Anda untuk REA! [Buat issue](https://github.com/morluto/rea/issues) untuk melaporkan bug atau menyarankan fitur, atau [kirim pull request](https://github.com/morluto/rea/pulls) untuk meningkatkan kode atau dokumentasi.

Lihat [CONTRIBUTING.md](../../CONTRIBUTING.md) untuk penyiapan pengembangan dan pemeriksaan, [pengujian](../testing.md) untuk tahapan verifikasi, serta [peta arsitektur](../architecture.mermaid) untuk struktur proyek.

## Lisensi

[MIT](../../LICENSE)

REA-authored code is licensed under MIT. Third-party material retains its own
licenses and copyright notices; see [Third-party notices](../../THIRD_PARTY_NOTICES.md)
for the dependency inventory, preserved license texts, and external-tool terms.

**You must legally obtain and be authorized to use commercial tools**, including
IDA Pro / Hex-Rays decompilers, Hopper, and JEB, under their applicable licenses.
REA grants no tool license, key, or activation entitlement. Trials and demos
remain subject to vendor terms, including user, feature, automation, and output
sharing restrictions. Cracked copies, stolen keys, unauthorized key sharing,
and bypassing license restrictions are not authorized. This guidance does not
amend MIT or third-party licenses.

---

> **Local expansion fork:** this fork (`jakestrouse00/rea`, upstream `morluto/rea`) re-enables categories upstream disables (fuzzing, interception, active replay) and adds the provider lanes listed under [Expansion fork capabilities](#expansion-fork-capabilities). Scope decisions are recorded in [CONTRIBUTING.md](CONTRIBUTING.md#contribution-scope). Nothing here is published upstream.

## Expansion fork capabilities

All lanes follow the upstream contract recipe: fail-closed `REA_*` configuration,
value-free Evidence with inline limitations, and offline test coverage. Provider
setup (`REA_*` environment variables and interpreter/venv choices) lives in the
[reverse-engineering tools guide](docs/reverse-engineering-tools.md); each page
below states its verified scope — most lanes are verified offline against
scripted fakes and fixtures, with real-provider verification steps documented
for the host owner.

| Capability                  | Facts reported                                                                                                                        | External tools                                                                                                                 | Guide |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ----- |
| iOS images (IPSW/OTA)       | Build inventory, Dyld shared-cache image manifests, ObjC/Swift class tables, crash symbolication                                      | Caller-supplied blacktop/ipsw; [ipsw guide](docs/ipsw-analysis.md)                                                             |
| Mach-O entitlements         | Entitlement/load-command structure for any Mach-O; values withheld, keys and kinds only                                               | Same ipsw binary; [ipsw guide](docs/ipsw-analysis.md)                                                                          |
| Binary capabilities         | Matched rule ids, locations and counts (capa, Ghidra backend optional)                                                                | Caller-supplied capa; [capa guide](docs/capa-analysis.md)                                                                      |
| Scanning with rules         | Rule id, offsets and matched fields; shipped hash-pinned crypto-constant pack                                                         | Caller-supplied YARA-X; [scanning guide](docs/yara-scanning.md)                                                                |
| Symbol recovery             | Go symbols, demangled Rust names and breakpad symbol tables for stripped binaries                                                     | Caller-supplied GoReSym, rustfilt (LLVM), dump_syms; [symbol guide](docs/symbol-recovery.md)                                   |
| .NET decompilation          | Typed member/declaration structure; decompiled text kept out of Evidence                                                              | Caller-supplied ilspycmd; [.NET decompilation](docs/dotnet-decompilation.md)                                                   |
| JVM decompilation           | Jar/class declaration structure for desktop bytecode                                                                                  | Caller-supplied Vineflower jar + JDK; [JVM decompilation](docs/jvm-decompilation.md)                                           |
| Python bytecode             | Compiled module structure and declaration recovery                                                                                    | Caller-supplied pycdc or PyLingual launcher; [Python decompilation](docs/python-decompilation.md)                              |
| protobuf/gRPC recovery      | Recovered `.proto` structure from binaries/APKs/JARs; lab-only gRPC reflection                                                        | Caller-supplied pbtk, protodump, grpcurl; [protobuf recovery](docs/protobuf-recovery.md)                                       |
| Binary diffing              | Match tables (similarity, confidence, names changed) as provider-backed input to behavioral comparison                                | Caller-supplied BinDiff/BinExport; [diffing guide](docs/binary-diffing.md)                                                     |
| V8 bytecode                 | Header/structure facts and disassembly handoff, sanitized through the script-evidence gate                                            | Locally built View8 binaries; [V8 bytecode](docs/v8-bytecode.md)                                                               |
| ASAR integrity              | Verified/mismatched member accounting and V8-bytecode handoff candidates                                                              | None (static reads); [ASAR integrity](docs/asar-integrity.md)                                                                  |
| Isolated emulation          | Bounded function emulation: register/memory structure, executed edges, exit reason; patch assembly                                    | Caller-supplied Unicorn 2.1.x + Keystone venv; [emulation](docs/emulation.md)                                                  |
| Symbolic execution          | Path conditions, exploration and CFG cross-checks; solver values redacted                                                             | Caller-supplied angr 9.2.x venv; [angr guide](docs/angr-symbolic-execution.md)                                                 |
| Fuzzing campaigns           | Engine adapters (libFuzzer, AFL++ FRIDA, Jackalope), stats streams, POV-validated crashes into the dedup pipeline; sandboxed launches | Caller-supplied engines; [campaigns](docs/fuzzing-campaigns.md)                                                                |
| Crash triage                | ASan/TSan/UBSan + macOS report parsing, crash-state hashing, dedup store, minimization hooks                                          | None (pure) + caller-supplied minimizers; [crash triage](docs/crash-triage.md)                                                 |
| HTTP replay                 | One-shot, never-retrying re-dispatch and mutation of captured or drafted requests; bodies never inline                                | None; [replay client](docs/replay-client.md)                                                                                   |
| Authorized browser mutation | Page evaluation, request-rule interception and page-context fetch through the same send core                                          | The REA-launched browser; [browser analysis](docs/browser-observation.md)                                                      |
| mitmproxy interception      | Structure-only endpoint inventory, standing rewrite rules, same send core for replay                                                  | Caller-supplied mitmproxy 12.x; [interception guide](docs/mitm-interception.md)                                                |
| Protocol learning           | FSA models from pcap/qlog captures, sandboxed lab probes, grammar handoff to campaigns                                                | Caller-supplied tshark fixture lane; [protocol learning](docs/protocol-learning.md)                                            |
| Investigation queue         | Ledger-driven scheduling, durable resumable queue, directory/device/endpoint watch sessions                                           | None (composes existing lanes); [hunting queue](docs/hunting-queue.md)                                                         |
| Lab VMs                     | Lima VM sessions (vz driver, Rosetta), command execution with scrubbed output                                                         | Caller-supplied Lima; [lab VMs](docs/lab-vms.md)                                                                               |
| Runtime presets             | Hash-pinned Frida bypass presets, whitelist-able objection recipes, BLE GATT bridge                                                   | Caller-supplied objection/bleak; [presets](docs/frida-script-presets.md), [mobile toolchain](docs/mobile-runtime-toolchain.md) |
| Benchmark/eval harness      | CTF-style task scoring inside lab VMs and offline Loop A/B/C eval fixtures                                                            | Caller-supplied Lima lane; [benchmark harness](docs/benchmark-harness.md)                                                      |
| Autonomous execution policy | sandbox-exec SBPL templates, lab-owned scoping, end-to-end smoke walkthrough                                                          | None; [policy](docs/autonomous-execution.md), [walkthrough](docs/autonomy-walkthrough.md)                                      |

The active request plane is disabled until the operator enables it: set
`REA_REPLAY_ALLOWED_ORIGINS` to exact origins, or to `*` to open the whole plane
at operator authority (one decision, no per-session declarations). See the
[replay client guide](docs/replay-client.md#enabling-the-plane).
