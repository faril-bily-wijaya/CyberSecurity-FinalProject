# Red Team Final Project: Web Application Penetration Testing

Dokumen ini mendefinisikan ruang lingkup, aturan keterlibatan (Rules of Engagement), metodologi, dan standar pelaporan untuk proyek akhir Red Team. Target utama dari pengujian ini adalah aplikasi web (website) pemerintahan dengan Top-Level Domain (TLD) `.go.id`.

Pengerjaan proyek ini dialokasikan selama kurang lebih 3 hingga 4 minggu.

## 1. Scope & Rules of Engagement (RoE)

Pengujian ini bersifat *Authorized* (Resmi dan Diizinkan) dengan syarat target telah menetapkan aturan keterbukaan kerentanan. 

### Target Scope
* **Primary Target:** Web application dengan ekstensi domain `.go.id`.
* **Prasyarat Target:** Target **DIWAJIBKAN** memiliki tim CSIRT (Computer Security Incident Response Team) yang terdaftar atau memiliki program VDP (Vulnerability Disclosure Program) yang mengizinkan pengujian keamanan independen. 
* Penguji wajib mematuhi batasan ruang lingkup yang ditetapkan oleh masing-masing CSIRT instansi terkait.

### Batasan Pengujian (Strictly Prohibited Actions)
Pengujian **TIDAK BOLEH** bersifat destruktif. Segala bentuk temuan hanya dieksploitasi sebatas *Proof of Concept* (PoC). Tindakan berikut adalah ilegal dalam lingkup proyek ini dan akan mengakibatkan diskualifikasi:
* **Server/Web Defacement:** Mengubah, merusak, atau mengganti halaman web target.
* **Domain Takeover / DNS Hijacking:** Mengambil alih kepemilikan atau merutekan ulang domain instansi.
* **Data Wiping / Modification:** Menghapus, mengenkripsi (Ransomware-like), atau memodifikasi data produksi pada infrastruktur target.
* **Denial of Service (DoS / DDoS):** Melakukan eksploitasi yang menyebabkan layanan target terhenti atau tidak dapat diakses.
* **Social Engineering / Phishing:** Terhadap pegawai atau pengguna layanan instansi terkait.

## 2. Metodologi Penetration Testing

Proses penetrasi dilakukan secara runtut namun tidak perlu didokumentasikan terlalu detail pada bagian ini, melainkan fokus pada eksekusi teknis. Urutan pengujian mencakup:

1. **Reconnaissance (Information Gathering):** Pengumpulan informasi target secara pasif dan aktif (Subdomain enumeration, port scanning, OSINT).
2. **Vulnerability Analysis:** Identifikasi titik lemah pada aplikasi web (Mapping application surface, input vectors).
3. **Exploitation:** Pembuktian kerentanan melalui eksploitasi yang aman (Safe exploitation) untuk menyusun PoC tanpa merusak integritas data target.
4. **Post-Exploitation:** (Sangat dibatasi) Hanya dilakukan untuk membuktikan besaran dampak kerentanan (impact analysis), seperti membaca file `/etc/passwd` tanpa melakukan eskalasi hak akses lebih lanjut secara merusak.
5. **Reporting:** Penyusunan laporan teknis sesuai format standar industri.

## 3. Sistem Penilaian dan Skala Keparahan (Severity & Point System)

Penilaian Final Project sangat bergantung pada metrik *Severity* kerentanan yang berhasil ditemukan dan didokumentasikan. Skala keparahan menggunakan basis CVSS 3.1 dan dikategorikan menggunakan kode warna sebagai representasi visual tingkat bahaya.

| Tingkat Keparahan | Kode Warna | Rentang CVSS 3.1 | Poin Evaluasi | Contoh Kerentanan |
| :--- | :--- | :--- | :--- | :--- |
| **Critical** | <span style="color:#FF0000; font-weight:bold;">Merah (Red)</span> | 9.0 - 10.0 | **100 Poin** | Remote Code Execution (RCE), SQL Injection (Data Exfiltration) |
| **High** | <span style="color:#FF8C00; font-weight:bold;">Oranye (Orange)</span> | 7.0 - 8.9 | **75 Poin** | Stored XSS, CSRF (pada fungsi kritikal), IDOR (Sensitive Data) |
| **Medium** | <span style="color:#FFD700; font-weight:bold;">Kuning (Yellow)</span> | 4.0 - 6.9 | **50 Poin** | Reflected XSS, CSRF (Low Impact), Subdomain Takeover (Non-critical) |
| **Low** | <span style="color:#008000; font-weight:bold;">Hijau (Green)</span> | 0.1 - 3.9 | **25 Poin** | Information Disclosure, Open Redirect, Missing Secure Flags |
| **Informational** | <span style="color:#0000FF; font-weight:bold;">Biru (Blue)</span> | 0.0 | **10 Poin** | Server Version Disclosure, Missing Security Headers |

*Catatan: Poin dapat diakumulasikan dari beberapa temuan, namun kualitas dokumentasi (Reporting) memegang persentase kelulusan yang tinggi.*

## 4. Standar Penulisan Laporan (Reporting Template)

Setiap temuan harus didokumentasikan menggunakan format yang jelas dan terstruktur. Laporan ini akan diserahkan untuk proses validasi. Berikut adalah contoh format wajib penulisan temuan (mengadopsi standar Bug Bounty / HTB):

---

### Example: Reporting CSRF

**Title:** Cross-Site Request Forgery (CSRF) in Consumer Registration
**CWE:** CWE-352: Cross-Site Request Forgery (CSRF)
**CVSS 3.1 Score:** 5.4 (Medium)

**Description:**
During our testing activities, we identified that the web page responsible for consumer registration is vulnerable to Cross-Site Request Forgery (CSRF) attacks.

Cross-Site Request Forgery (CSRF) is an attack where an attacker tricks the victim into loading a page that contains a malicious request. It is malicious in the sense that it inherits the identity and privileges of the victim to perform an undesired function on the victim's behalf, like change the victim's e-mail address, home address, or password, or purchase something. CSRF attacks generally target functions that cause a state change on the server but can also be used to access sensitive data.

**Impact:**
The impact of a CSRF flaw varies depending on the nature of the vulnerable functionality. An attacker could effectively perform any operations as the victim. Because the attacker has the victim's identity, the scope of CSRF is limited only by the victim's privileges. 

Specifically, an attacker can register a user application and create an API key as the victim in this case.

**POC (Proof of Concept):**

* **Step 1:** Using an intercepting proxy, we looked into the request to create a new application profile. We noticed no anti-CSRF protections being in place.
* **Step 2:** We used the abovementioned request to craft a malicious HTML page that, if visited by a victim with an active session, a cross-site request will be performed, resulting in the advertent creation of an attacker-specific application account.
* **Step 3:** To complete the attack, we would have to send our malicious web page to a victim having an open session. The following image displays the actual cross-site request that would be issued if the victim visited our malicious web page.
  *(Masukkan Screenshot Intercept Request HTTP di sini)*
* **Step 4:** The result would be the inadvertent creation of a new application account by the victim. It should be noted that this attack could have taken place in the background if combined with finding 6.1.1 (e.g., an XSS vulnerability).
  *(Masukkan Screenshot Hasil Eksekusi di sini)*

**CVSS Score Breakdown:**

* **Attack Vector:** Network - The attack can be mounted over the internet.
* **Attack Complexity:** Low - All the attacker has to do is trick a user that has an open session into visiting a malicious website.
* **Privileges Required:** None - The attacker needs no privileges to mount the attack.
* **User Interaction:** Required - The victim must click a crafted link provided by the attacker.
* **Scope:** Unchanged - Since the vulnerable component is the webserver and the impacted component is again the webserver.
* **Confidentiality:** Low - The attacker can create an application and obtain limited information.
* **Integrity:** Low - The attacker can modify data (create an application) but limitedly and without seriously affecting the vulnerable component's integrity.
* **Availability:** None - The attacker cannot perform a denial-of-service through this CSRF attack.

---
