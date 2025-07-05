# 🕵️‍♂️ CodeAlpha Network Sniffer

A modern, interactive Python tool for exploring and analyzing network traffic in real time.  
Easily capture, inspect, and log packets with a vibrant, user-friendly terminal interface.

---

## 🌟 Highlights

- **Real-Time Capture:** Instantly view packets as they appear on your network.
- **Multi-Protocol Support:** Handles TCP, UDP, ICMP, and more.
- **Vivid Terminal Output:** Uses color to distinguish protocols and warnings.
- **Live Protocol Stats:** See protocol counts as you capture.
- **Flexible Interface Selection:** Choose your network interface (Linux).
- **Protocol Filtering:** Focus on TCP, UDP, or ICMP traffic as needed.
- **CSV Logging:** Save packet summaries for later analysis.
- **Hex & ASCII Views:** Examine both raw and readable payloads.
- **Cross-Platform:** Works on Linux and Windows (admin/root required).
- **Easy to Extend:** Clean, well-commented code for learning and customization.

---

## 🖼️ Preview

![demo](https://github.com/Pumkin0071/Code_Alpha_Tasks_CyberSecurity/blob/main/Network%20Sniffer%20Screenshot.png)

---

## ⚙️ Getting Started

### 1. Requirements

No extra packages needed—just Python 3.x.

### 2. Launching the Sniffer

```bash
# On Linux (run as root)
sudo python3 "Basic Network Sniffer.py" [options]

# On Windows (run as Administrator)
python "Basic Network Sniffer.py" [options]
```

### 3. Command-Line Options

| Option              | Purpose                                         |
|---------------------|------------------------------------------------|
| `-c`, `--count`     | Limit the number of packets captured           |
| `-p`, `--protocol`  | Filter by protocol: `tcp`, `udp`, or `icmp`    |
| `-i`, `--interface` | Specify network interface (Linux only)         |
| `-l`, `--log`       | Save packet details to a CSV file              |

#### Usage Examples

```bash
# Capture 10 TCP packets on eth0 and save to packets.csv
sudo python3 "Basic Network Sniffer.py" -c 10 -p tcp -i eth0 -l packets.csv

# Capture all packets on the default interface
sudo python3 "Basic Network Sniffer.py"
```

---

## 🔒 Permissions & Notes

- **Linux:** Run as `root` (use `sudo`).
- **Windows:** Run as Administrator.
- If you encounter permission errors, check your privileges.

---

## 🛠️ How It Works

- Uses ANSI codes for colorful output.
- Parses Ethernet, IP, TCP, UDP, and ICMP headers.
- Displays live protocol statistics.
- Modular and easy to expand for new features.

---

## 📖 For Learners & Researchers

This project is intended for educational and authorized research purposes only.  
**Never use it on networks without explicit permission.**

---

## 👤 Author

Created by **Shounak Gan** for the CodeAlpha Cybersecurity Internship 2025.  
Designed from scratch for clarity, learning, and hands-on exploration of network traffic.

---

## 💡 Want to Contribute?

Ideas, improvements, and pull requests are always welcome!  
Fork the project and make it your own.

---

**Explore your network. Learn by doing. Enjoy the colorful world of packets!**
