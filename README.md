# unban – Fail2ban IP/subnet unban tool with optional ignoreip addition

`unban` is a command-line tool written in Go that interacts with Fail2ban to remove bans for specific IP addresses or subnets. It supports two modes:

1. **Simple unban** (without modifying ignoreip) – just remove the ban and, if necessary, split larger banned subnets to keep other IPs banned.
2. **Unban + ignoreip** (with `-i` flag) – after unbanning, adds the IP/subnet to the `ignoreip` list in the corresponding jail configuration file(s), preserving multi-line formatting and sorting entries.

hp Features

- Detects all active jails via `fail2ban-client status`.
- Retrieves banned IPs/subnets per jail.
- Handles exact matches and subnet containment (e.g., if a larger subnet contains the target).
- For contained subnets: unbans the whole subnet, splits it into smaller pieces excluding the target, and re-bans the pieces.
- Supports IPv4 and IPv6 (but subnet splitting is only implemented for IPv4).
- Logs all actions to both stdout and a log file (default `/var/log/unban.log`).
- When `-i` is used:
  - Finds the correct configuration file(s) for each affected jail (`jail.local`, `jail.conf`, or files in `/etc/fail2ban/jail.d/`).
  - Creates a timestamped backup before modifying.
  - Extracts existing `ignoreip` entries (handling multi-line values with backslash continuations).
  - Adds the new IP/subnet if not already present, removes duplicates.
  - Sorts entries in a human-friendly order:
    - IPv4 before IPv6.
    - For IPv4: loopback (`127.0.0.0/8`) first, then private RFC1918 + link-local, then public.
    - Within each group, sorted by numeric IP address and then by mask (more specific first).
  - Reformats the `ignoreip` block with proper indentation and backslashes.
- Supports a positional argument for simple unban (no ignoreip).

## Installation

```bash
git clon https://github.com/yourname/unban-tool
cd unban-tool
go build -o unban main.go
sudo cp unban /usr/local/bin/
```

## Usage

```text
Usage: unban [options] [<ip/subnet>]

Options:
  -h          Show this help
  -v          Show version
  -l <file>    Set log file (default /var/log/unban.log)
  -i <ip/subnet> Unban the given IP or subnet and add it to ignoreip in jail config
```
If `-i` is given, the IP/subnet is added to ignoreip. Without `-i`, the first positional argument is unbanned without modifying ignoreip.

## Examples

Simple unban (no ignoreip):
```bash
sudo unban 192.168.1.100
sudo unban 10.0.0.0/24
```

Unban and add to ignoreip:
```bash
sudo unban -i 192.168.1.100
sudo unban -i 10.0.0.0/24
```

Using custom log file:
```bash
sudo unban -i 192.168.1.100 -l /tmp/my.log
```

---

## How it works

1. **Parse input:** The tool accepts either a plain HP (converted internally to /32 or /128) or a CIDR subnet (any mask).
2. **Get jails:** Runs `fail2ban-client status` to list all active jails.
3. **Get banned entries:** For each jail, runs `fail2ban-client status <jail>` and extracts the Banned IP list.
4. **Find affected jails:** For each banned entry, it checks if the target matches exactly or is contained within a larger banned subnet.
5. **Process each jail:** 
    - If exact match: simply aunbanip`.
    - If contained in a larger subnet:
      - Unban the larger subnet.
      - Split the larger subnet recursively until the target is isolated, resulting in a set of subnets that do not include the target.
      - Re-ban each of those resulting subnets.
6. **If ignore mode:**
    - Search for the jail definition in all known config files (`jail.local`, `jail.conf`, `jail.d/*.conf`).
    - When found, create a backup (`<filename>.<timestamp>`).
    - Extract existing `ignoreip` values, even if they span multiple lines with backslashes.
    - Adds the new IP/subnet (if not already present), sort, and format back with proper indentation.
    - Write the updated file.

## Important notes

- The tool must be run as **root** (or with sudo) because it executes `fail2ban-client` and modifies system configuration files.
- Subnet splitting currently only works for **IPv4**. IPv6 subnets that contain the target will be handled by unbanning the whole subnet without re‑banning the rest (a warning is logged).
- When adding to `ignoreip`, the tool preserves the original configuration file structure (comments, other settings) and only modifies the `ignoreip` block inside the relevant jail section.
- **Sorting order:**
    1. IPv4 addresses/networks (Loopback -> Private -> Public).
    2. IPv6 addresses/networks.

## Troubleshooting

- If you see warnings about invalid IPs in `ignoreip`, check that the entries are correctly formatted. The tool tries to parse each token and ignores those that fail.
- If the tool cannot find a jail definition in any config file, it will attempt to add the `ignoreip` to `/etc/fail2ban/jail.local` (creating it if necessary).
- **Always check the backups before reloading fail2ban to verify changes.**
