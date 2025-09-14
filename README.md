# 🛡️ Secure Network with pfSense, Suricata, Wazuh, and Honeypot

This project demonstrates a secure network architecture featuring **firewall protection**, **intrusion detection/prevention**, **centralized log management**, and **threat intelligence** using honeypots.  
It is designed to detect, prevent, and analyze attacks in real time.

---

## 📌 Network Diagram
Below is the network topology for this project:

![Network Diagram](./475d6cad-2e40-4d62-9930-64f591492fc0.png)

---

## 🚀 Components Overview

### **1. pfSense Firewall & Suricata IDS/IPS**
- **pfSense** is the main firewall and gateway managing network traffic.
- **Suricata** is installed on pfSense for intrusion detection and prevention.
- Key features:
  - Block **port scanning attacks** (e.g., Nmap).
  - Detect and mitigate **DoS/DDoS attacks** by filtering large or spam packets.
  - Configure **NAT** to allow internal networks to access the internet.
  - Control **ICMP (ping)** between networks to allow or block communication.

---

### **2. Wazuh Manager & Agents**
- **Wazuh Manager** collects and analyzes logs from all monitored devices.
- Internal machines run **Wazuh Agents** to send logs and activity data to the manager.

#### 🔹 Key Wazuh Features:
- **Active Response**  
  - Scans the `Downloads` folder using the **VirusTotal API**.
  - Automatically **deletes infected files** if malware is detected.
- **Brute Force Protection**  
  - Detects repeated failed login attempts.
  - **Blocks the attacker's IP** automatically.

---

### **3. Honeypot for Threat Intelligence**
- A **Honeypot** is deployed to lure hackers and study attack behavior.
- Features:
  - Opens multiple fake services and ports to attract attackers.
  - Records all interactions and sends logs to **Wazuh Manager**.
  - Helps improve detection rules and security awareness.

---

## 🌐 Network Segmentation
| Network            | Purpose                    | Example IPs           |
|--------------------|---------------------------|-----------------------|
| **External (WAN)** | Simulated attacker network | `172.16.69.0/24`      |
| **Internal LAN**   | Wazuh Manager, Agents, Clients | `192.168.100.0/24` |
| **DMZ**            | Public-facing servers (Web, Honeypot) | `192.168.120.0/24` |

---

## ⚙️ Project Workflow
1. **Hacker launches attack** from the external network.  
2. **pfSense + Suricata** detect and block malicious traffic (e.g., port scanning, DoS).  
3. **Honeypot** attracts attackers, logs activity, and sends data to Wazuh Manager.  
4. **Wazuh** analyzes logs and takes **automated actions**:
   - Quarantine or delete malware.
   - Block brute force attack IPs.
   - Generate alerts for security teams.

---

## 🛠 Tools & Technologies
- **pfSense** – Firewall and network management  
- **Suricata** – Intrusion Detection/Prevention System (IDS/IPS)  
- **Wazuh** – Security Information and Event Management (SIEM)  
- **VirusTotal API** – Malware scanning and detection  
- **Honeypot** – Threat intelligence and attack simulation  
- **VMware** – Virtual network simulation

---

## 📖 How to Use
1. **Set up virtual network** in VMware or GNS3 using the provided topology.
2. Configure **pfSense** firewall rules and enable Suricata.
3. Deploy **Wazuh Manager** and **Wazuh Agents** on client machines.
4. Configure **Honeypot** with open ports to attract attackers.
5. Launch simulated attacks (e.g., Nmap, DoS) and observe detection and response.

---

## 🧾 Summary
This setup provides:
- **Proactive defense** using IDS/IPS and firewall rules.
- **Centralized log management and threat analysis** with Wazuh.
- **Automated response** to malware and brute-force attacks.
- **Threat intelligence gathering** via honeypot.

By combining these tools, this project demonstrates a complete cybersecurity ecosystem for detecting and responding to modern threats.

---

## DEMO
![Image](https://github.com/user-attachments/assets/154d120d-4e75-4bc5-affb-ae5f78ca0fd4)


https://www.youtube.com/playlist?list=PLFb35DC5uB-rrCvG3pnqJfI2yZtSu7_3t

