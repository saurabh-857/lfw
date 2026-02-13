# lfw – Linux Firewall (NFQUEUE-based)

![Project](https://img.shields.io/badge/lfw-purple.svg)
![Language](https://img.shields.io/badge/C11-blue.svg)

## lfw – Linux Firewall (NFQUEUE-based)

`lfw` is a simple Linux firewall daemon that reads rules from a text file (similar to ufw syntax) and enforces them using the Linux Netfilter NFQUEUE mechanism.

### 1. Features

- **NFQUEUE-based daemon**: inspects packets from an `iptables` NFQUEUE and decides to ACCEPT or DROP.
- **Stateful connection tracking**: tracks established connections (5-tuple) and allows subsequent packets without re-evaluating rules, improving performance and supporting connection-oriented protocols.
- **Human-readable rules file**: simple syntax like `allow tcp 22` or `deny any`.
- **IPv4 + TCP/UDP/ICMP support**.
- **Configurable rules path**: default `/etc/lfw/lfw.rules`, or custom path via CLI argument.

---

### 2. Requirements

- **Linux** with Netfilter / `iptables`.
- **GCC** (or compatible C compiler).
- **libnetfilter_queue** development headers.
- **libpcap** development headers (only needed for the optional pcap test tool).

On Debian/Ubuntu/Kali, you can install dependencies with:

```bash
sudo apt update
sudo apt install build-essential libnetfilter-queue-dev libpcap-dev
```

---

### 3. Build

From the project root:

```bash
make
```

This will:

- Build the main firewall daemon: `build/lfw`
- (Optionally) you can build the pcap test tool with:

```bash
make pcap-test
```

To clean:

```bash
make clean
```

---

### 4. Rules file

By default, `lfw` reads rules from:

- `/etc/lfw/lfw.rules`

You can also pass a custom rules file path as the first CLI argument:

```bash
sudo build/lfw /path/to/custom.rules
```

#### 4.1 Syntax

One rule per line:

```text
ACTION [PROTO] [PORT] [from SRC] [to DST]
```

- **ACTION**: `allow` | `deny` (or `drop`)
- **PROTO**: `any` | `tcp` | `udp` | `icmp` (optional, default: any)
- **PORT**: integer port (e.g. `22`), or `PORT/PROTO` (e.g. `53/udp`) (optional; matches destination port)
- **SRC/DST**: `any` or IPv4 address (e.g. `192.168.1.10`)

Lines starting with `#` or empty lines are ignored.

#### 4.2 Examples

```text
# Allow HTTP
allow tcp 80

# Allow SSH
allow tcp 22

# Allow DNS from a specific host
allow 53/udp from 192.168.1.53

# Deny everything else
deny any
```

Place your rules into `/etc/lfw/lfw.rules` (or another file you pass on the command line).

---

### 5. Running the firewall

#### 5.1 Prepare the rules file

Create the directory and copy your rules:

```bash
sudo mkdir -p /etc/lfw
sudo cp lfw.rules /etc/lfw/lfw.rules
```

Edit `/etc/lfw/lfw.rules` as needed (see examples above).

#### 5.2 Configure iptables NFQUEUE

`lfw` expects packets to be delivered via an NFQUEUE. You can configure this manually or use the provided helper script.

**Option A: Using the helper script**

A `route.sh` script is provided to simplify iptables NFQUEUE setup:

```bash
# Add NFQUEUE rules (uses mangle table for PREROUTING and OUTPUT)
sudo ./route.sh 1

# Remove NFQUEUE rules
sudo ./route.sh 2
```

**Option B: Manual iptables configuration**

For a simple setup that sends all incoming packets to queue `0`:

```bash
sudo iptables -I INPUT -j NFQUEUE --queue-num 0
```

For more comprehensive filtering (including forwarded and outgoing traffic), you can use the mangle table:

```bash
sudo iptables -I PREROUTING -t mangle -j NFQUEUE --queue-num 0
sudo iptables -I OUTPUT -t mangle -j NFQUEUE --queue-num 0
```

You can customize your `iptables` rules as you like, as long as the traffic you want filtered is sent to the same queue number that `lfw` uses (default: `0`).

To remove rules later:

```bash
# Remove INPUT rule
sudo iptables -D INPUT -j NFQUEUE --queue-num 0

# Or remove mangle table rules
sudo iptables -D PREROUTING -t mangle -j NFQUEUE --queue-num 0
sudo iptables -D OUTPUT -t mangle -j NFQUEUE --queue-num 0
```

> **Note**: On systems using `nftables` or firewalld, you may prefer to configure NFQUEUE with those tools instead of raw `iptables`.

#### 5.3 Start the daemon

Run `lfw` as root (or with sufficient capabilities) so it can interact with Netfilter:

```bash
cd /path/to/lfw
sudo build/lfw
```

If you want to use a custom rules file:

```bash
sudo build/lfw /path/to/custom.rules
```

While running, `lfw` will log decisions like:

```text
[lfw] ALLOW tcp 192.168.1.10:54321 -> 192.168.1.2:22
[lfw] DENY tcp 203.0.113.5:43210 -> 192.168.1.2:80
```

Stop the daemon with `Ctrl+C`.

---

### 6. Stateful filtering

`lfw` includes stateful connection tracking by default. This means:

- **New connections**: When a new connection (e.g., TCP SYN packet) arrives, it is evaluated against your ruleset. If allowed, the connection is added to the state table.
- **Established connections**: Subsequent packets belonging to an already-allowed connection are automatically accepted without re-evaluating rules, improving performance.
- **Connection tracking**: The firewall tracks connections using a 5-tuple (source IP, destination IP, source port, destination port, protocol) with a fixed-size hash table (4096 entries).

Stateful filtering works for TCP and UDP connections. ICMP packets are handled statelessly.

If the connection state table cannot be allocated (e.g., out of memory), `lfw` will fall back to stateless operation and log a warning.

---

### 7. Default policy & failure behavior

- If the rules file loads successfully, the **default action** is **ACCEPT**, and traffic is evaluated against your rules.
- If the rules file cannot be loaded, `lfw` falls back to **deny all inbound** for any packets it sees on the NFQUEUE (i.e. default action becomes DROP).

---

### 8. Quick start (TL;DR)

```bash
# 1) Install dependencies (Debian/Ubuntu/Kali)
sudo apt update
sudo apt install build-essential libnetfilter-queue-dev libpcap-dev

# 2) Build
cd /path/to/lfw
make

# 3) Install rules
sudo mkdir -p /etc/lfw
sudo cp lfw.rules /etc/lfw/lfw.rules

# 4) Route packets to NFQUEUE 0 (choose one method)
# Option A: Use helper script (recommended)
sudo ./route.sh 1

# Option B: Manual iptables setup
sudo iptables -I INPUT -j NFQUEUE --queue-num 0

# 5) Run the firewall daemon
sudo build/lfw
```

After this, your incoming packets that hit the NFQUEUE rule will be filtered according to `lfw.rules`.

