---

# 🌐 Packet Sniffer for Network Traffic Analysis 🚨

A Python-based tool to capture, log, and visualize network traffic—perfect for cybersecurity enthusiasts, SOC analysts, and aspiring penetration testers. This sniffer detects suspicious activity such as potential brute-force attacks, captures DNS/HTTP traffic, and even visualizes packet volume in real time.

---

## 📌 About

Welcome to **Packet Sniffer**, a tool crafted for hands-on network traffic analysis. Whether you're monitoring threats or mapping traffic patterns, this project gives you insight into HTTP requests, DNS queries, and potential attack behavior.

Built using `scapy`, this tool logs critical traffic details, detects anomalies, and produces a traffic volume chart via `matplotlib`. Ideal for home lab environments like Kali Linux or TryHackMe, it’s a great stepping stone in any cybersecurity journey.

---

## ✨ Features

* 🎯 Captures **HTTP (port 80)** and **DNS (port 53)** traffic with customizable filters.
* 🚨 Flags suspicious behavior like repeated HTTP 401 Unauthorized responses.
* 📊 Plots packet volume over time using `matplotlib`.
* 📝 Logs traffic details to `packet_sniffer.log`.
* ⚡ Supports command-line options for interface, packet count, and BPF filters.
* 🛡️ Designed for **ethical use** in a **lab environment**.

---

## 🧰 Requirements

* Python **3.6+**
* Libraries: `scapy`, `matplotlib`
* **Root/admin privileges** for packet capture
* A safe testing setup (e.g., Kali Linux VM + Metasploitable)

---

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/packet-sniffer.git
cd packet-sniffer
```

### 2. Install Dependencies

```bash
pip install scapy matplotlib
```

### 3. Run the Sniffer

Basic usage (captures 100 packets on the default interface):

```bash
sudo python3 packet_sniffer.py
```

Specify an interface and packet count:

```bash
sudo python3 packet_sniffer.py -i eth0 -c 50
```

Apply a custom filter (e.g., only capture HTTP):

```bash
sudo python3 packet_sniffer.py -f "tcp port 80"
```

---

## 📂 Output

* **Logs**: Saved to `packet_sniffer.log`
* **Graph**: Saved as `traffic_volume.png`

---

## 🧪 Testing Scenarios

* **Localhost**: Start a web server with `python -m http.server 80` and generate traffic by browsing to `http://localhost`.
* **Lab Network**: Use Metasploitable to simulate DNS lookups or brute-force login attempts.
* **Public Target**: With permission, capture traffic to/from `scanme.nmap.org`.

> Example:

```bash
sudo python3 packet_sniffer.py -i eth0 -c 200
```

Captures 200 packets on `eth0`, logs activity, and produces a traffic volume plot.

---

## 🔧 Room for Improvement

* 🛠 Add real-time alerting (email, Slack) for flagged activity.
* 📈 Upgrade visualization using interactive dashboards (e.g., Plotly).
* 🔍 Expand detection rules (e.g., SQL injection patterns).
* 🧩 Save traffic in `.pcap` format for Wireshark analysis.

---

## ⚠️ Notes & Legal

* 🚫 **Use responsibly**. Unauthorized packet sniffing is illegal.
* ⚙️ Run with `sudo` or admin rights to capture raw packets.
* 🧪 Use tools like TryHackMe, Kali, and Metasploitable for safe and ethical experimentation.

---

## 👤 Credits

Built by **\[Angel Alicea]** as part of my transition into cybersecurity!
Inspired by real-world traffic analysis, Wireshark exploration, and a passion for network security.
Powered by the amazing [`scapy`](https://scapy.net/) and [`matplotlib`](https://matplotlib.org/).

---

**Happy sniffing — and stay secure! 🔒**

---
