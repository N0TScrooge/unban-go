# unban-go
A Go tool to unban IPs or subnets from fail2ban jails. It handles exact matches and subnet containment by splitting larger banned subnets and re-banning the remainder. Optionally adds the target to ignoreip with automatic backup, multi-line formatting, and smart sorting (loopback, private, public).
