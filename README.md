# lfw – Linux Firewall

![Project](https://img.shields.io/badge/lfw-purple.svg)
![Language](https://img.shields.io/badge/C11-blue.svg)

`lfw` is a stateful Linux firewall daemon that intercepts packets using the Netfilter NFQUEUE mechanism and evaluates them against a human-readable ruleset.


## 1. Features

* **NFQUEUE-based daemon**: Intercepts packets from `iptables` and issues ACCEPT or DROP verdicts.
* **Stateful connection tracking**: Tracks established 5-tuple connections (Source IP, Destination IP, Source Port, Destination Port, Protocol) to bypass rule evaluation for existing sessions.
* **Human-readable rules**: Simple syntax for managing traffic permissions.
* **IPv4 Support**: Full support for TCP, UDP, and ICMP over IPv4.


## 2. Requirements

To build and run `lfw`, you need the following:

* **Linux** with `iptables` support.
* **GCC** with C11 support.
* **Libraries**: `libnetfilter_queue` and `libpcap` (for the test tool).

On Debian/Ubuntu:

```bash
sudo apt install build-essential libnetfilter-queue-dev libpcap-dev
```


## 3. Build & Installation

Clone the repo & navigate to the `lfw` repo:

```bash
git clone https://github.com/saurabh-857/lfw.git
cd lfw
```

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


## 4. Configuration

By default, `lfw` reads rules from:

- `/etc/lfw/lfw.rules`

You can also pass a custom rules file path as the first CLI argument:

```bash
sudo build/lfw /path/to/custom.rules
```

### 4.1 Syntax

One rule per line:

```text
ACTION [PROTO] [PORT] [from SRC] [to DST]
```

- **ACTION**: `allow` | `deny` (or `drop`)
- **PROTO**: `any` | `tcp` | `udp` | `icmp` (optional, default: any)
- **PORT**: integer port (e.g. `22`), or `PORT/PROTO` (e.g. `53/udp`) (optional; matches destination port)
- **SRC/DST**: `any` or IPv4 address (e.g. `192.168.1.10`)

Lines starting with `#` or empty lines are ignored.

### 4.2 Examples

```text
# Deny by default
default deny

# Allow HTTP
allow tcp 80

# Allow SSH
allow tcp 22

# Allow DNS from a specific host
allow 53/udp from 192.168.1.53

# Allow to specific host or router
allow any from 192.168.1.1

# Allow ICMP
allow icmp
```

Place your rules into `/etc/lfw/lfw.rules` (or another file you pass on the command line).


## 5. Running the firewall

### 5.1 Prepare the rules file

Create the directory and copy your rules:

```bash
sudo mkdir -p /etc/lfw
sudo cp lfw.rules /etc/lfw/lfw.rules
```

Edit `/etc/lfw/lfw.rules` as needed (see examples above).

### 5.2 Start the daemon

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
[lfw] ALLOW in  tcp    192.168.0.101:52084 ->   192.168.0.102:8081 
[lfw] ALLOW out tcp    192.168.0.102:8081  ->   192.168.0.101:52084
```

Stop the daemon with `Ctrl+C`.


## 6. Internal Architecture

* **Core Engine**: Orchestrates the lookup process, checking the state table before the rule list.
* **State Table**: A hash table with 4096 entries used to track active TCP and UDP connections.
* **Packet Parser**: Extracts L3 and L4 headers from raw NFQUEUE data.
* **Config Loader**: Parses text-based rule files into memory.


## 7. Quick start (TL;DR)

```bash
# 1) Install dependencies (Debian/Ubuntu/Kali)
sudo apt install build-essential libnetfilter-queue-dev libpcap-dev

# 2) Build
cd /path/to/lfw
make

# 3) Install rules
sudo mkdir -p /etc/lfw
sudo cp lfw.rules /etc/lfw/lfw.rules

# 4) Run the firewall daemon
sudo build/lfw
```

After this, your incoming packets that hit the NFQUEUE rule will be filtered according to `lfw.rules`.

