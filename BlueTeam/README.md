# Blue Team Final Project: Defensive Security & Threat Analysis

Dokumen ini mendefinisikan ruang lingkup, metodologi, dan standar pelaporan untuk proyek akhir Blue Team. Fokus utama dari domain ini adalah deteksi ancaman, analisis artefak berbahaya, dan pemantauan infrastruktur keamanan.

Peserta dapat memilih salah satu dari tiga kategori proyek di bawah ini untuk diselesaikan dan dipresentasikan.

---

## Kategori Proyek Blue Team

### 1. Malicious File Analysis (Malware Analysis)
Proyek ini berfokus pada analisis dinamis dan statis terhadap sampel malware. Sampel dapat diambil dari repositori publik seperti MalwareBazaar atau platform intelijen ancaman lainnya. Analisis wajib didokumentasikan dalam bentuk *Write-up* yang komprehensif. Penggunaan platform *sandbox* seperti ANY.RUN sangat disarankan untuk mendapatkan metrik MITRE ATT&CK dan *Indicators of Compromise* (IoC).

### 2. SIEM Deployment & Configuration (Wazuh)
Proyek ini berfokus pada perancangan, instalasi, dan konfigurasi sistem Wazuh (baik secara *Cloud-based* maupun *On-Premise*). Laporan harus mendetailkan arsitektur yang digunakan, konfigurasi *agent-manager*, serta pembuatan *custom rules* untuk mendeteksi anomali spesifik. Fokus utama penilaian adalah pada kemampuan sistem saat didemonstrasikan (Live Demo).

### 3. Digital Forensics & Reverse Engineering
Proyek ini mencakup investigasi mendalam terhadap artefak digital, *memory forensics*, atau *reverse engineering* terhadap *binary* berbahaya. Penjelasan teknis mengenai metode ini akan diberikan lebih lanjut pada sesi *briefing* sebelum presentasi akhir.

---

## Aturan Keterlibatan (Rules of Engagement)

* **Isolation:** Seluruh analisis malware yang bersifat dinamis wajib dilakukan di dalam lingkungan yang terisolasi (Virtual Machine dengan *Host-Only Adapter* atau *Cloud Sandbox*).
* **No Live Execution on Host:** Dilarang keras mengeksekusi sampel malware di mesin utama (Host OS).
* **Defanged IoCs:** Seluruh IoC berupa domain atau IP berbahaya di dalam laporan harus disamarkan (contoh: `malicious[.]com` atau `192[.]168[.]1[.]1`).

---

## Standar Penulisan Laporan (Reporting Template)

Berikut adalah format wajib untuk pelaporan kategori **Malicious File Analysis**. Laporan ini harus mencakup taktik, teknik, dan prosedur (TTPs) berdasarkan MITRE ATT&CK Framework.

### Example: ANY.RUN Malware Analysis Write-up

**Title:** Dynamic Analysis of Suspicious COM Surrogate Execution
**Date:** [Tanggal Analisis]
**Analyst:** [Nama Peserta]

#### 1. File Information & Threat Verdict
* **Filename:** `suspicious_sample.exe` (Contoh)
* **Threat Verdict:** Malicious (Score: 100/100)
* **Tags:** `Privilege Escalation`, `Masquerading`, `Registry Modification`
* **Target OS:** Windows 10 (64-bit)

#### 2. Executive Summary
Sampel ini dieksekusi di lingkungan *sandbox* dan segera menunjukkan aktivitas berbahaya dengan melakukan injeksi atau penyamaran ke dalam proses sistem Windows yang sah. Proses utama yang terdeteksi melakukan anomali adalah `dllhost.exe` (COM Surrogate).

#### 3. Execution & Process Tree
Proses mengeksekusi `dllhost.exe` dengan parameter *command line* spesifik untuk menyembunyikan aktivitasnya.
* **Process Name:** `dllhost.exe`
* **Path:** `C:\Windows\System32\dllhost.exe`
* **Command Line:** `C:\WINDOWS\system32\DllHost.exe /Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}`

#### 4. MITRE ATT&CK Framework Mapping
Berdasarkan analisis perilaku, sampel ini memicu beberapa taktik dan teknik MITRE ATT&CK:

| Tactic | Technique ID | Technique Name | Description / Event |
| :--- | :--- | :--- | :--- |
| **Execution** | T1204.002 | User Execution: Malicious File | Malware dieksekusi oleh pengguna awal. |
| **Privilege Escalation** | T1548.002 | Bypass User Account Control | Memanfaatkan mekanisme kontrol elevasi yang diketahui (*Known privilege escalation attack*). |
| **Defense Evasion** | T1036.005 | Masquerading: Match Legitimate Resource | Menyamar sebagai proses sistem yang sah (`dllhost.exe`) untuk menghindari deteksi. |
| **Defense Evasion / Persistence** | T1112 | Modify Registry | Melakukan modifikasi pada *registry key* sistem. |
| **Discovery** | T1012 | Query Registry | Membaca pengaturan keamanan (contoh: membaca pengaturan keamanan Internet Explorer). |
| **Command and Control** | T1071 | Application Layer Protocol | Membangun komunikasi keluar (*outbound*) menggunakan protokol lapisan aplikasi. |

#### 5. Indicators of Compromise (IoC) & Indicators of Attack (IoA)

**Host-Based Indicators (IoA/IoC):**
* **Modified Registry Keys:** Terdapat modifikasi pada *registry* untuk mempertahankan persistensi dan eskalasi hak akses (UAC Bypass).
* **Process Anomaly:** Eksekusi `dllhost.exe` dengan *ProcessID* GUID yang mencurigakan tanpa pemanggilan COM objek yang valid dari aplikasi standar.

**Network-Based Indicators (IoC):**
* *(Masukkan IP, Domain, atau URL yang dihubungi oleh malware saat fase C&C, pastikan format telah di-defang)*.
* **Protocol:** HTTP/HTTPS (Application Layer Protocol).

#### 6. Recommendations & Mitigation
* Terapkan aturan EDR/SIEM untuk memantau eksekusi `dllhost.exe` yang memicu pemanggilan *registry* terkait UAC (*User Account Control*).
* Batasi hak akses pengguna lokal (Standard User) untuk mencegah eskalasi hak akses secara otomatis.
* Lakukan isolasi terhadap *endpoint* yang terindikasi menjalankan proses *masquerading* ini.

---
