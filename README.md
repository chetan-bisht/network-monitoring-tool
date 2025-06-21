# Interactive Network Monitor with Geolocation

A desktop application built with Python and Tkinter for live network traffic monitoring. This tool provides a user-friendly interface to capture and analyze network packets in real-time, helping users understand the activity on their network, including the physical location of remote servers.

---

## Features Showcase

This tool provides multiple, powerful views to analyze network traffic from different perspectives.

**1. Protocol Distribution:** See a real-time breakdown of traffic by protocol. This view provides an immediate understanding of the *type* of traffic on your network. This capture of over 5,200 packets shows a typical internet browsing session, where the tool correctly identifies **TCP** as the dominant protocol (89.9%), used for web traffic, while also categorizing essential **UDP** traffic and other IP-based packets.
![Protocol Distribution View](screenshot-protocols-distribution.png)

**2. IP Traffic & Hostname Resolution:** View the top IP addresses sending traffic and their resolved hostnames. This powerful feature separates internal network devices (like `192.168.0.1`) from public internet servers. The Hostname column showcases the application's non-blocking architecture:
-   It displays **`Resolving...`** for new IPs without freezing the UI.
-   It successfully resolves hostnames like **`...googleusercontent.com`**.
-   It gracefully handles addresses with no record as **`N/A`**.
-   It even detects its own meta-traffic to **`ip-api.com`**, proving its comprehensive capture capabilities.
![IP Traffic View](screenshot-ip-traffic.png)

**3. Live Geolocation:** Discover the geographical origin of network packets. This unique view aggregates all traffic by country, providing a high-level understanding of your computer's global connections. The example clearly shows a global footprint, with significant traffic from servers located in the **United States, Germany, and India**. This feature makes it easy to visualize where data is coming from and can instantly highlight unexpected international activity.
![Geolocation View](screenshot-geolocation.png)

---

## Key Features

- **Live Packet Sniffing:** Captures network packets in real-time using the powerful Scapy library.
- **Interactive Controls:** Easy-to-use Start and Stop buttons to control the capture session.
- **Smart Interface Selection:** Automatically filters the network interface list to show only active, usable adapters.
- **Multi-Tabbed Data Views:** Analyze data by Protocol, IP Address, and Geolocation.
- **Hostname & Geolocation Resolution:** Enriches raw IP addresses with human-readable hostnames and country data for easier identification.
- **Responsive UI:** A multi-threaded architecture ensures the user interface never freezes, even while performing slow network lookups.

---

## Requirements

- Python 3.7+
- `pip` (The Python package installer)

---

## Setup and Installation

Follow these steps to get the application running on your local machine.

**1. Get the Code**
Download all the project files (`app.py`, `requirements.txt`, etc.) into a single folder on your computer.

**2. Install Dependencies**
Open a terminal or command prompt and navigate to your project folder. Then, install the required libraries using `pip`.
```bash
pip install -r requirements.txt
```

---

## How to Run

**⚠️ Important: Administrator Privileges Required!**

To capture network packets, this application **must** be run with administrator or root privileges.

**On Windows:**
1. Open **Command Prompt** or **PowerShell** as an **Administrator**.
2. Navigate to the project directory where you saved `gui_app.py`.
3. Run the application:
```bash
python gui_app.py
```

**On macOS / Linux:**
1. Open a terminal.
2. Navigate to the project directory where you saved `gui_app.py`.
3. Run the application using `sudo`:
```bash
sudo python3 gui_app.py
```
