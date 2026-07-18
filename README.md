# lfw – Linux Firewall

![Project](https://img.shields.io/badge/lfw-purple.svg)
![Language](https://img.shields.io/badge/C11-blue.svg)

`lfw` is a high-performance stateful Linux firewall daemon that intercepts and filters packets in-kernel using eBPF at the Traffic Control (TC) subsystem, evaluating them against a human-readable ruleset.


## 1. Features

* **eBPF/TC-based filtering**: Intercepts packets in-kernel at the Traffic Control (TC) ingress/egress hooks and issues high-performance ACCEPT or DROP/SHOT verdicts.
* **Stateful connection tracking**: Tracks active 5-tuple connections (Source IP, Destination IP, Source Port, Destination Port, Protocol) for both IPv4 and IPv6, with a background thread that periodically purges expired connections.
* **Subnet/CIDR Matching**: Supports bitwise subnet masking for both IPv4 and IPv6 rule definitions (e.g. `/24`, `/64`, `/32`, or `any`).
* **FQDN / Domain Name Matching**: Supports specifying domain names (e.g. `google.com` or `facebook.com`) directly in rules, resolved in userspace and updated dynamically.
* **Port Range Support**: Allows matching destination ports by ranges (e.g. `67-68` or `546-547`) or single ports.
* **Thread-Safe Architecture**: Full concurrency protection utilizing reader-writer locks (`pthread_rwlock_t`) for rules evaluation/reload and mutexes (`pthread_mutex_t`) for connection tracking.
* **On-the-fly Config Reload (SIGHUP)**: Dynamic reload of rulesets without terminating the daemon or dropping active connection tracking states.
* **Operational Metrics (SIGUSR1)**: Real-time statistics dump of rule hits, throughput bytes, and connection counts (both IPv4 and IPv6) directly to syslog.
* **Production Logging**: Integration with `syslog` for structured, JSON-based telemetry.
* **Dual-Stack Support**: Full stateful filtering support for IPv4 and IPv6 TCP, UDP, and ICMP/ICMPv6.


## 2. Requirements

To build and run `lfw`, the following requirements must be met:

* **Linux** kernel supporting eBPF and Traffic Control (TC) clsact.
* **GCC** with C11 support.
* **Libraries**: `libbpf` and `libpcap` (for the test tool).
* **Compilers**: `clang` and `llvm` (to compile the eBPF kernel program).

On Debian/Ubuntu:

```bash
sudo apt install build-essential clang llvm libbpf-dev libpcap-dev
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

This compiles:
- The main firewall daemon: `build/lfw`
- The eBPF kernel program: `build/lfw_bpf.o`

To install the daemon, configuration rules, and systemd service globally on the system:

```bash
sudo make install
```

### Running Unit Tests

The codebase includes a suite of unit tests verifying raw packet parsing, CIDR subnet matching, connection tracking (including thread-safety and concurrency), and stateful behavior:

```bash
make test
```

### Running Offline PCAP Tests

The rule engine can be run offline against a pcap or pcapng packet capture file to verify verdicts without attaching to live network interfaces.

First, build the pcap test utility:
```bash
make pcap-test
```

Then run the tester with the sample pcapng file:
```bash
./build/lfw_pcap_test wireshark_packet_capture.pcapng lfw.rules
```

To clean build artifacts:
```bash
make clean
```


## 4. Configuration

By default, `lfw` reads rules from:

- `/etc/lfw/lfw.rules`

A custom rules file path can also be passed as the second CLI argument after the interface:

```bash
sudo build/lfw <interface> /path/to/custom.rules
```

### 4.1 Syntax

One rule per line:

```text
ACTION [PROTO] [PORT] [from SRC] [to DST]
```

- **ACTION**: `allow` | `deny` (or `drop`)
- **PROTO**: `any` | `tcp` | `udp` | `icmp` | `igmp` | `icmpv6` | `esp` | `ah` (optional, default: any)
- **PORT**: single port (e.g. `22`), port range (e.g. `67-68`), or `PORT/PROTO` (e.g. `53/udp`) (optional; matches destination port/range)
- **SRC/DST**: `any`, IPv4 address (e.g. `192.168.1.10`), IPv6 address (e.g. `2001:db8::1`), IPv4 CIDR (e.g. `192.168.1.0/24`), IPv6 CIDR (e.g. `2001:db8::/32`), or FQDN/domain name (e.g. `google.com`)

Lines starting with `#` or empty lines are ignored.

### 4.2 Examples

```text
# Deny by default
default deny

# Optional: Completely block an IP version (must be placed at the top)
# deny from 0.0.0.0/0   # Completely block all IPv4 traffic
# deny from ::/0        # Completely block all IPv6 traffic

# Allow loopback interface traffic
allow tcp from 127.0.0.0/8 to 127.0.0.0/8
allow udp from 127.0.0.0/8 to 127.0.0.0/8
allow icmp from 127.0.0.0/8 to 127.0.0.0/8
allow tcp from ::1 to ::1
allow udp from ::1 to ::1
allow icmp from ::1 to ::1

# Allow DHCPv4 and DHCPv6 client ports
allow udp 67-68
allow udp 546-547

# Allow HTTPS from anywhere
allow tcp 443

# Allow DNS queries to a specific resolver
allow udp 53 to 8.8.8.8

# Allow HTTP from a local IPv6 subnet
allow tcp 80 from 2001:db8::/32

# Allow ICMP & ICMPv6 (Ping & Neighbor Discovery)
allow icmp
allow icmpv6

# Allow IPsec VPN traffic
allow esp
allow ah

# Block distracting websites by FQDN domain (must precede general allows)
deny tcp 443 to facebook.com
deny tcp 443 to twitter.com

# Allow specific enterprise services by FQDN domain
allow tcp 443 to github.com
allow tcp 443 to google.com
```

Place rules into `/etc/lfw/lfw.rules` (or another file specified on the command line).

### 4.3 Log Levels

To optimize performance and control logging verbosity, `lfw` supports configurable log levels. Logging verbosity can be set at four levels:

*   **`minimal`**: Bypasses the telemetry pipeline completely. Only errors are logged to the console/syslog.
*   **`optimal`** (default): Recommended for production. Captures daemon reloads and dropped packets (alarms/verdict events), but ignores allowed packet logs to prevent disk flooding.
*   **`max`**: Captures all packet actions (both `ALLOW` and `DROP` logs).
*   **`super_max`**: Captures all packet actions, details conntrack GC sweeps, and enables in-kernel debug tracing via `bpf_printk` (visible in `/sys/kernel/debug/tracing/trace_pipe`).

#### Configuration via Rules File

Define the log level in `/etc/lfw/lfw.rules` using the `loglevel` keyword:

```text
loglevel optimal
```

This can be updated dynamically on-the-fly without stopping the firewall daemon by reloading configuration using the `SIGHUP` signal.

#### Command-Line Override

You can override the rules file's log level at startup using the `--log-level` parameter:

```bash
sudo build/lfw <interface> --log-level super_max
```


## 5. Running the Firewall

### 5.1 Prepare the Rules File

Create the directory and copy the rules:

```bash
sudo mkdir -p /etc/lfw
sudo cp lfw.rules /etc/lfw/lfw.rules
```

Edit `/etc/lfw/lfw.rules` as needed (see examples above).

### 5.2 Start the daemon

Run `lfw` as root and specify the network interface to attach to:

```bash
cd /path/to/lfw
sudo build/lfw <interface>
```

For example, to run on the loopback (`lo`) interface or ethernet (`eth0`):

```bash
sudo build/lfw lo
```

To use a custom rules file:

```bash
sudo build/lfw <interface> /path/to/custom.rules
```

### 5.3 System Logs & Signals

Operational events and logs are sent to the system logger (`syslog`). Real-time log events can be viewed using syslog:
```bash
tail -f /var/log/syslog | grep lfw
```

Or by querying the systemd journal logs:
```bash
journalctl -t lfw -f
```

The daemon also supports operational control signals:

- **Reload Config**: Reload the rules configuration file dynamically without restarting:
  ```bash
  sudo kill -HUP $(pgrep lfw)
  ```
- **Dump Statistics**: Output active connections table size, rule hit counts, and byte counters to syslog:
  ```bash
  sudo kill -USR1 $(pgrep lfw)
  ```

## 5.4 Systemd & NetworkManager Integration

For automatic integration with the host network configuration, `lfw` uses systemd template service units coupled with a NetworkManager dispatcher script (installed globally via `sudo make install`).

### Automatic Activation
During `sudo make install`, the installer automatically discovers all physical network interfaces on the host (e.g., `eth0`, `wlan0`) and flags them as enabled by touching files in `/etc/lfw/interfaces.enabled/`.

### NetworkManager Dispatcher
A dispatcher script is placed at `/etc/NetworkManager/dispatcher.d/99-lfw-dispatcher`. Whenever an interface goes up or down, NetworkManager invokes this dispatcher which:
- Automatically starts or restarts `lfw@<interface>` when the link comes up (crucial to recreate eBPF/TC attachments after events like MAC address randomization).
- Automatically stops `lfw@<interface>` when the interface link goes down.

To enable automatic firewall startup on `eth0`:
```bash
sudo touch /etc/lfw/interfaces.enabled/eth0
```

To disable automatic firewall startup on `eth0`:
```bash
sudo rm -f /etc/lfw/interfaces.enabled/eth0
```

### Manual Control
The firewall daemon can also be manually managed on a specific interface using standard systemd commands:

- **Start** the firewall on `eth0`:
  ```bash
  sudo systemctl start lfw@eth0
  ```
- **Stop** the firewall on `eth0`:
  ```bash
  sudo systemctl stop lfw@eth0
  ```
- **Check running status** for `eth0`:
  ```bash
  sudo systemctl status lfw@eth0
  ```


## 6. Internal Architecture

* **eBPF Filter**: Intercepts packets directly in the kernel's TC ingress and egress pipelines, parsing packet headers (L3/L4) and matching them against active rules and connections for sub-microsecond filtering.
* **State/Conntrack Maps**: 
  - `conntrack_map`: A BPF Hash Map tracking active IPv4 connections.
  - `conntrack_map_v6`: A BPF Hash Map tracking active IPv6 connections.
  - Both track stateful TCP connections (SYN-SENT, SYN-RECV, ESTABLISHED, FIN-WAIT) and UDP flows. Out-of-state TCP packets (e.g., non-SYN packets arriving before connection establishment) are dropped.
* **Rules Map**: A BPF Array Map (`rules_details_map`) populated by the userspace daemon containing up to 256 compiled rules.
* **Config Map**: A BPF Array Map (`config_map`) storing runtime configuration parameters (e.g., default action and rule count).
* **Trie Maps**: LPM (Longest Prefix Match) Trie maps (`src_ip_trie`, `dst_ip_trie`, `src_ip6_trie`, `dst_ip6_trie`) populated by the userspace daemon for high-performance bitwise subnet/CIDR matching.
* **Transitive Nested Subnets Rule Mask Merging**: Because eBPF LPM trie lookups only return the most specific matching prefix, rules configured for larger enclosing subnets or "any" IP would normally be bypassed. The userspace daemon solves this by dynamically propagating (OR'ing) rule bitmasks from parent subnets down to their nested child subnets during synchronization, ensuring accurate rule evaluation in $O(\log N)$ in-kernel lookups.
* **eBPF Ring Buffer Telemetry**: A high-performance BPF Ring Buffer map (`events_ringbuf`) used to stream real-time packet verdicts (ALLOW, DROP) and header metadata from the kernel filter directly to userspace.
* **Background Housekeeper**: A userspace thread that periodically sweeps `conntrack_map` and `conntrack_map_v6` in the kernel and deletes expired connections using state-specific timeouts (e.g. shorter timeouts for unfinished TCP handshakes).
* **Background FQDN Resolver**: A userspace thread that periodically (every 60 seconds) resolves FQDN rules to active IP addresses. If resolved IPs change, it reloads rules atomically using a mutex lock to guarantee thread safety.
* **Config Loader**: Parses text-based rules files in userspace, executes transitive rule mask merging, and synchronizes compiled rule structures, policies, and tries to the BPF maps.


## 7. Quick Start (TL;DR)

### 1. Install Dependencies (Debian/Ubuntu)
```bash
sudo apt install -y build-essential clang llvm libbpf-dev libpcap-dev
```

### 2. Clone & Navigate to the Folder
```bash
git clone https://github.com/saurabh-857/lfw.git
cd lfw
```

### 3. Build & Install System-wide
```bash
make
sudo make install
```

### 4. Verify Firewall Status
The firewall is automatically enabled on all physical interfaces upon installation. The running status can be checked on a specific interface (e.g., `wlan0`):
```bash
sudo systemctl status lfw@wlan0
```

After this, incoming and outgoing packets on the enabled interfaces will be filtered according to `/etc/lfw/lfw.rules`.


## 8. License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.


