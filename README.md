# Decepti-WiFi

A powerful tool for creating deceptive WiFi access points and conducting network security testing using an ESP8266 microcontroller. This project implements a rogue access point (AP) with an integrated captive portal, DNS server, and HTTP server to simulate legitimate networks for security research and testing purposes.

## Features

- **Rogue Access Point Creation**: Set up custom WiFi networks with spoofed SSID and MAC addresses
- **Captive Portal**: Display a fake login page to capture user credentials
- **DNS Server**: Redirect all DNS queries to the AP's IP address for seamless phishing
- **HTTP Server**: Lightweight web server handling requests and responses with minimal overhead
- **Credential Capture**: Automatically log and store captured email/password combinations
- **Network Scanning**: Scan and display nearby WiFi networks with detailed information (SSID, BSSID, channel, signal strength, security type)

## Project Structure

### Core Components

**`captive_portal.py`**
- Main orchestrator for the deceptive WiFi AP
- Manages WiFi network connections and scans
- Handles rogue AP configuration and startup
- Coordinates DNS and HTTP servers through an event poller
- Stores network credentials for reconnection

**`server.py`**
- HTTP server implementation optimized for embedded systems (MicroPython)
- Handles HTTP/1.1 requests with streaming responses
- Routes requests to appropriate handlers (login forms, redirects)
- Implements request parsing and URL decoding
- Manages socket connections with minimal memory overhead

**`captive_dns.py`**
- DNS server that intercepts DNS queries
- Redirects all domain lookups to the AP's IP address (192.168.4.1)
- Ensures users are directed to the captive portal regardless of their destination

**`MITM.py`**
- Credential management and storage
- Reads/writes captured email and password combinations to logs
- Validates credential integrity before storage

### HTML & Interface

**`index.html`**
- Phishing login page displayed to users
- Styled web interface for credential capture
- Tricks users into entering email and password

**`error.html`**
- Error/success page shown after login attempt

### Utilities

**`main.py`**
- Entry point for the application
- Initializes and starts the CaptivePortal

**ESP8266 Firmware**
- `esp8266-512k-20220618-v1.19.1.bin`: MicroPython firmware for ESP8266
- `ampy`: Tool for file management on the microcontroller
- `rshell`: Remote shell utility for ESP8266 communication

## How It Works

1. **Initialization**: Device connects to a legitimate WiFi network using stored credentials
2. **Network Scanning**: Displays nearby WiFi networks to inform setup
3. **Rogue AP Setup**: Creates a custom access point with user-specified:
   - SSID (network name)
   - MAC address (spoofed)
   - Security mode (Open or WPA2-PSK)
4. **Request Interception**: 
   - DNS server redirects all queries to the AP
   - Any HTTP request is redirected to the captive portal login
5. **Credential Capture**: When users enter credentials on the fake login page, they are logged to `logs.txt`
6. **Event Loop**: Continuously polls for DNS and HTTP events, processing them with minimal latency

## Technical Highlights

- **Event-Driven Architecture**: Uses MicroPython's `uselect.poll()` for efficient I/O multiplexing
- **Memory Optimization**: Stream-based HTTP response handling with 536-byte buffers (TCP MSS size)
- **Embedded Systems Focus**: Designed for resource-constrained ESP8266 (512KB RAM)
- **Non-Blocking Sockets**: Asynchronous handling of multiple client connections

## Usage

> ⚠️ **Warning**: This tool is designed for authorized security testing and research only. Unauthorized network access is illegal. Always ensure you have proper authorization before using this tool.

1. Flash the ESP8266 with the included MicroPython firmware
2. Upload all Python scripts and HTML files to the device
3. Run `main.py` to start the application
4. Follow the prompts to:
   - Enter your WiFi network credentials
   - Review nearby networks
   - Configure the rogue access point details
5. Monitor the console for client connections and captured credentials

## Files Generated at Runtime

- `creds.txt`: Stores WiFi network credentials for connection
- `logs.txt`: Contains captured email/password combinations

## Requirements

- ESP8266 microcontroller with 512KB+ memory
- MicroPython firmware (included)
- Network connection for initial scanning

## Disclaimer

This project is provided for educational and authorized security testing purposes only. Users are responsible for complying with all applicable laws and regulations regarding network security testing in their jurisdiction. Unauthorized access to computer networks is illegal.

## License

