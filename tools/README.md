## lfw_pcap_test – Offline lfw tester

`lfw_pcap_test` is a small helper tool that lets you run the **same rule engine and config** as the main `lfw` daemon, but against packets stored in a **pcap file** instead of live NFQUEUE traffic.

### Build

From the project root:

```bash
make pcap-test
```

This produces:

- `build/lfw_pcap_test`

### Usage

```bash
./build/lfw_pcap_test <file.pcap> [rules_file]
```

- **`<file.pcap>`**: required; the pcap file to replay.
- **`[rules_file]`**: optional path to an lfw rules file.
  - If omitted, defaults to `/etc/lfw/lfw.rules` (same as the main daemon).

Examples:

```bash
# Use system rules (/etc/lfw/lfw.rules)
./build/lfw_pcap_test samples/traffic.pcap

# Use a custom rules file in the repo
./build/lfw_pcap_test samples/traffic.pcap ./lfw.rules
```

### Behaviour

- Rules and default policy are loaded via `lfw_config_load_file`, just like `src/main.c`.
- If the rules file cannot be loaded, the tool falls back to:
  - **empty ruleset**
  - **default action = DROP** (deny all inbound), same as the daemon’s failure behaviour.
- For each IPv4 packet in the pcap:
  - The tool skips the 14‑byte Ethernet header.
  - Parses the packet with `lfw_parse_ipv4_packet(..., LFW_DIR_INBOUND, ...)`.
  - Evaluates it with `lfw_engine_evaluate`.
  - Prints a line such as:

```text
packet verdict: ACCEPT
packet verdict: DROP
```

