package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	version = "1.0.0"
)

var (
	logFile      string
	ignoreValue  string
	ignoreMode   bool // true if -i flag was used
	showHelp     bool
	showVersion  bool
	positionalIP string // IP/subnet from positional argument
)

func init() {
	flag.StringVar(&logFile, "l", "/var/log/unban.log", "log file path")
	flag.StringVar(&ignoreValue, "i", "", "IP or subnet to unban and add to ignoreip in jail config")
	flag.BoolVar(&showHelp, "h", false, "show help")
	flag.BoolVar(&showVersion, "v", false, "show version")
	flag.Usage = usage
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: unban [options] [<ip/subnet>]

Options:
  -h          Show this help
  -v          Show version
  -l <file>   Set log file (default /var/log/unban.log)
  -i <ip/subnet> Unban the given IP or subnet (IPv4, /32 - /23) and add it to ignoreip in jail config

If -i is given, the IP/subnet is added to ignoreip. Without -i, the first positional argument is unbanned without modifying ignoreip.
If no arguments provided, version and help are shown.
`)
}

func main() {
	flag.Parse()

	// Check for positional argument
	args := flag.Args()
	if len(args) > 0 {
		positionalIP = args[0]
	}

	// Determine mode
	if (ignoreValue == "" && positionalIP == "") || showHelp || showVersion {
		if showVersion {
			fmt.Printf("unban version %s\n", version)
		}
		if showHelp || (ignoreValue == "" && positionalIP == "") {
			usage()
		}
		return
	}

	logWriter, err := setupLogging(logFile)
	if err != nil {
		log.Fatalf("Failed to set up logging: %v", err)
	}
	log.SetOutput(logWriter)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	log.Println("Starting unban tool")

	targetStr := ignoreValue
	ignoreMode = (ignoreValue != "")
	if !ignoreMode {
		targetStr = positionalIP
	}
	log.Printf("Target: %s (ignore mode: %v)", targetStr, ignoreMode)

	parsed, err := parseIPOrSubnet(targetStr)
	if err != nil {
		log.Fatalf("Invalid IP/subnet: %v", err)
	}
	log.Printf("Parsed target: %s", parsed.String())

	if err := processUnban(parsed); err != nil {
		log.Fatalf("Processing failed: %v", err)
	}

	log.Println("Unban completed successfully")
}

// runCommand executes an external command and logs it
func runCommand(name string, args ...string) ([]byte, error) {
	cmdStr := name + " " + strings.Join(args, " ")
	log.Printf("Executing: %s", cmdStr)
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Command failed: %s, error: %v, output: %s", cmdStr, err, string(out))
	} else {
		log.Printf("Command succeeded: %s, output: %s", cmdStr, string(out))
	}
	return out, err
}

func setupLogging(logPath string) (io.Writer, error) {
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	return io.MultiWriter(os.Stdout, file), nil
}

// parseIPOrSubnet parses IP or subnet. For IPv4 any mask is allowed, for IPv6 also.
func parseIPOrSubnet(s string) (*net.IPNet, error) {
	// Try as IP
	if ip := net.ParseIP(s); ip != nil {
		if ip.To4() != nil {
			_, ipnet, err := net.ParseCIDR(s + "/32")
			return ipnet, err
		} else {
			_, ipnet, err := net.ParseCIDR(s + "/128")
			return ipnet, err
		}
	}
	// Try as CIDR
	ip, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, fmt.Errorf("invalid format: %v", err)
	}
	if ip.To4() == nil && ip.To16() == nil {
		return nil, fmt.Errorf("not a valid IP address")
	}
	return ipnet, nil
}

type jailInfo struct {
	name   string
	banned []*net.IPNet
}

func processUnban(target *net.IPNet) error {
	jails, err := getJails()
	if err != nil {
		return fmt.Errorf("failed to get jails: %v", err)
	}
	log.Printf("Found %d jails", len(jails))

	var jailList []*jailInfo
	for _, name := range jails {
		banned, err := getBannedIPs(name)
		if err != nil {
			log.Printf("Warning: cannot get banned list for jail %s: %v", name, err)
			continue
		}
		jailList = append(jailList, &jailInfo{name: name, banned: banned})
		log.Printf("Jail %s has %d banned entries", name, len(banned))
	}

	affectedJails := make(map[string][]*unbanAction)
	for _, ji := range jailList {
		actions := findActionsForTarget(ji, target)
		if len(actions) > 0 {
			affectedJails[ji.name] = actions
		}
	}

	if len(affectedJails) == 0 {
		log.Printf("Target %s not found in any jail", target.String())
		return nil
	}

	log.Printf("Target affects %d jails", len(affectedJails))

	for jailName, actions := range affectedJails {
		if err := processJail(jailName, actions); err != nil {
			log.Printf("Error processing jail %s: %v", jailName, err)
		}
	}

	// If ignore mode is enabled, add to ignoreip
	if ignoreMode {
		if err := addIgnoreIPToJails(affectedJails, target); err != nil {
			log.Printf("Failed to add ignoreip: %v", err)
		}
	} else {
		log.Println("Ignore mode not enabled, skip adding to ignoreip")
	}

	return nil
}

type unbanAction struct {
	banned     *net.IPNet
	isExact    bool
	containing []*net.IPNet
}

func findActionsForTarget(ji *jailInfo, target *net.IPNet) []*unbanAction {
	var actions []*unbanAction
	for _, b := range ji.banned {
		if ipsEqual(b, target) {
			actions = append(actions, &unbanAction{banned: b, isExact: true})
			continue
		}
		if contains(b, target) {
			actions = append(actions, &unbanAction{banned: b, containing: []*net.IPNet{target}})
		}
	}
	return actions
}

func ipsEqual(a, b *net.IPNet) bool {
	return a.String() == b.String()
}

func contains(parent, child *net.IPNet) bool {
	parentIs4 := parent.IP.To4() != nil
	childIs4 := child.IP.To4() != nil
	if parentIs4 != childIs4 {
		return false
	}
	pOnes, _ := parent.Mask.Size()
	cOnes, _ := child.Mask.Size()
	if pOnes > cOnes {
		return false
	}
	return parent.Contains(child.IP)
}

func processJail(jailName string, actions []*unbanAction) error {
	log.Printf("Processing jail %s", jailName)

	for _, act := range actions {
		if act.isExact {
			if err := unbanIP(jailName, act.banned.String()); err != nil {
				log.Printf("Failed to unban exact %s in %s: %v", act.banned.String(), jailName, err)
			} else {
				log.Printf("Unbanned exact %s from %s", act.banned.String(), jailName)
			}
		}
	}

	for _, act := range actions {
		if len(act.containing) > 0 {
			if err := unbanIP(jailName, act.banned.String()); err != nil {
				log.Printf("Failed to unban containing subnet %s in %s: %v", act.banned.String(), jailName, err)
				continue
			}
			log.Printf("Unbanned containing subnet %s from %s", act.banned.String(), jailName)

			toBan, err := splitSubnet(act.banned, act.containing[0])
			if err != nil {
				log.Printf("Failed to split subnet %s: %v", act.banned.String(), err)
				continue
			}
			for _, subnet := range toBan {
				if err := banIP(jailName, subnet.String()); err != nil {
					log.Printf("Failed to ban %s in %s: %v", subnet.String(), jailName, err)
				} else {
					log.Printf("Banned %s in %s", subnet.String(), jailName)
				}
			}
		}
	}
	return nil
}

func splitSubnet(parent, target *net.IPNet) ([]*net.IPNet, error) {
	var result []*net.IPNet
	var queue []*net.IPNet
	queue = append(queue, parent)

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if ipsEqual(current, target) {
			continue
		}

		if !contains(current, target) {
			result = append(result, current)
			continue
		}

		ones, bits := current.Mask.Size()
		if ones >= bits {
			result = append(result, current)
			continue
		}

		sub1, sub2, err := splitNetwork(current)
		if err != nil {
			return nil, err
		}
		queue = append(queue, sub1, sub2)
	}
	return result, nil
}

func splitNetwork(n *net.IPNet) (*net.IPNet, *net.IPNet, error) {
	ones, bits := n.Mask.Size()
	if ones >= bits {
		return nil, nil, fmt.Errorf("cannot split /32 or /128 network")
	}
	if n.IP.To4() != nil {
		// IPv4
		ip := n.IP.To4()
		step := uint32(1) << (bits - ones - 1)
		ipUint := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
		first := ipUint
		second := ipUint + step

		sub1, err := cidrFromUint32(first, ones+1)
		if err != nil {
			return nil, nil, err
		}
		sub2, err := cidrFromUint32(second, ones+1)
		if err != nil {
			return nil, nil, err
		}
		return sub1, sub2, nil
	} else {
		return nil, nil, fmt.Errorf("IPv6 subnet splitting not implemented")
	}
}

func cidrFromUint32(ipUint uint32, ones int) (*net.IPNet, error) {
	ip := net.IPv4(byte(ipUint>>24), byte(ipUint>>16), byte(ipUint>>8), byte(ipUint))
	_, ipnet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ip.String(), ones))
	return ipnet, err
}

func getJails() ([]string, error) {
	out, err := runCommand("fail2ban-client", "status")
	if err != nil {
		return nil, err
	}
	return parseJailList(string(out)), nil
}

func parseJailList(output string) []string {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Jail list:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			listStr := strings.TrimSpace(parts[1])
			if listStr == "" {
				return []string{}
			}
			items := strings.Split(listStr, ",")
			var jails []string
			for _, item := range items {
				jails = append(jails, strings.TrimSpace(item))
			}
			return jails
		}
	}
	return []string{}
}

func getBannedIPs(jail string) ([]*net.IPNet, error) {
	out, err := runCommand("fail2ban-client", "status", jail)
	if err != nil {
		return nil, err
	}
	return parseBannedList(string(out))
}

func parseBannedList(output string) ([]*net.IPNet, error) {
	lines := strings.Split(output, "\n")
	var banned []*net.IPNet
	for _, line := range lines {
		if strings.Contains(line, "Banned IP list:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			listStr := strings.TrimSpace(parts[1])
			if listStr == "" {
				return banned, nil
			}
			items := strings.Fields(listStr)
			for _, item := range items {
				ipnet, err := parseIPOrSubnet(item)
				if err != nil {
					log.Printf("Warning: failed to parse banned entry '%s': %v", item, err)
					continue
				}
				banned = append(banned, ipnet)
			}
			break
		}
	}
	return banned, nil
}

func unbanIP(jail, ip string) error {
	_, err := runCommand("fail2ban-client", "set", jail, "unbanip", ip)
	return err
}

func banIP(jail, ip string) error {
	_, err := runCommand("fail2ban-client", "set", jail, "banip", ip)
	return err
}

// ================== ignoreip configuration handling ==================

func addIgnoreIPToJails(affected map[string][]*unbanAction, target *net.IPNet) error {
	configFiles, err := findAllJailConfigs()
	if err != nil {
		return err
	}
	if len(configFiles) == 0 {
		return fmt.Errorf("no jail config files found")
	}
	log.Printf("Found %d potential config files", len(configFiles))

	for jailName := range affected {
		log.Printf("Looking for definition of jail '%s'", jailName)
		found := false
		for _, path := range configFiles {
			content, err := os.ReadFile(path)
			if err != nil {
				log.Printf("Warning: cannot read %s: %v", path, err)
				continue
			}
			lines := strings.Split(string(content), "\n")
			sectionRegex := regexp.MustCompile(`^\s*\[(` + regexp.QuoteMeta(jailName) + `)\]\s*$`)
			for _, line := range lines {
				if sectionRegex.MatchString(line) {
					log.Printf("Found jail '%s' in %s", jailName, path)
					backupFile := path + "." + time.Now().Format("02012006150405")
					if err := copyFile(path, backupFile); err != nil {
						log.Printf("Failed to create backup for %s: %v", path, err)
						continue
					}
					log.Printf("Backup created: %s", backupFile)

					if err := modifySingleJailConfig(path, jailName, target.String()); err != nil {
						log.Printf("Failed to modify %s: %v", path, err)
					} else {
						log.Printf("Successfully updated ignoreip in %s", path)
					}
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			log.Printf("Jail '%s' not found in any config file, will add to default jail.local", jailName)
			defaultPath := "/etc/fail2ban/jail.local"
			if _, err := os.Stat(defaultPath); os.IsNotExist(err) {
				if err := os.WriteFile(defaultPath, []byte(""), 0644); err != nil {
					log.Printf("Failed to create %s: %v", defaultPath, err)
					continue
				}
			}
			backupFile := defaultPath + "." + time.Now().Format("02012006150405")
			if err := copyFile(defaultPath, backupFile); err != nil {
				log.Printf("Failed to create backup for %s: %v", defaultPath, err)
				continue
			}
			log.Printf("Backup created: %s", backupFile)
			if err := modifySingleJailConfig(defaultPath, jailName, target.String()); err != nil {
				log.Printf("Failed to modify %s: %v", defaultPath, err)
			} else {
				log.Printf("Successfully updated ignoreip in %s", defaultPath)
			}
		}
	}
	return nil
}

func findAllJailConfigs() ([]string, error) {
	var paths []string
	basePaths := []string{
		"/etc/fail2ban/jail.local",
		"/etc/fail2ban/jail.conf",
	}
	for _, p := range basePaths {
		if _, err := os.Stat(p); err == nil {
			paths = append(paths, p)
		}
	}
	jailDPath := "/etc/fail2ban/jail.d"
	if entries, err := os.ReadDir(jailDPath); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".conf") {
				fullPath := filepath.Join(jailDPath, entry.Name())
				paths = append(paths, fullPath)
			}
		}
	} else if !os.IsNotExist(err) {
		log.Printf("Warning: cannot read %s: %v", jailDPath, err)
	}
	return paths, nil
}

func modifySingleJailConfig(path, jailName, ignoreValue string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(content), "\n")

	var outLines []string
	i := 0
	n := len(lines)

	sectionRegex := regexp.MustCompile(`^\s*\[(` + regexp.QuoteMeta(jailName) + `)\]\s*$`)

	for i < n {
		line := lines[i]
		if sectionRegex.MatchString(line) {
			outLines = append(outLines, line)
			i++

			var sectionLines []string
			for i < n && !isSectionStart(lines[i]) {
				sectionLines = append(sectionLines, lines[i])
				i++
			}
			newSectionLines := processJailSection(sectionLines, jailName, ignoreValue)
			outLines = append(outLines, newSectionLines...)
		} else {
			outLines = append(outLines, line)
			i++
		}
	}

	output := strings.Join(outLines, "\n")
	if !strings.HasSuffix(output, "\n") {
		output += "\n"
	}
	return os.WriteFile(path, []byte(output), 0644)
}

func isSectionStart(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]")
}

func processJailSection(lines []string, jailName, newIP string) []string {
	existingIPs := extractIgnoreIPs(lines)

	// Remove duplicates
	unique := make(map[string]*net.IPNet)
	for _, ip := range existingIPs {
		unique[ip.String()] = ip
	}
	existingIPs = make([]*net.IPNet, 0, len(unique))
	for _, ip := range unique {
		existingIPs = append(existingIPs, ip)
	}

	// Add new IP if not present
	newIPNet, err := parseIPOrSubnet(newIP)
	if err != nil {
		log.Printf("Warning: invalid new IP %s: %v", newIP, err)
	} else {
		if _, ok := unique[newIPNet.String()]; !ok {
			existingIPs = append(existingIPs, newIPNet)
		}
	}

	sortIPNets(existingIPs)
	ignoreLines := formatIgnoreIP(existingIPs)

	// Remove old ignoreip lines
	var result []string
	inIgnoreBlock := false
	ignorePattern := regexp.MustCompile(`^\s*ignoreip\s*=`)

	for _, line := range lines {
		if ignorePattern.MatchString(line) {
			inIgnoreBlock = true
			continue
		}
		if inIgnoreBlock {
			if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
				continue
			} else {
				inIgnoreBlock = false
			}
		}
		if !inIgnoreBlock {
			result = append(result, line)
		}
	}

	if len(ignoreLines) > 0 {
		if len(result) > 0 && strings.TrimSpace(result[len(result)-1]) != "" {
			result = append(result, "")
		}
		result = append(result, ignoreLines...)
	}
	return result
}

func extractIgnoreIPs(lines []string) []*net.IPNet {
	var ips []*net.IPNet
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if strings.Contains(line, "ignoreip") {
			re := regexp.MustCompile(`^\s*ignoreip\s*=\s*(.*)`)
			matches := re.FindStringSubmatch(line)
			if matches == nil {
				continue
			}
			value := strings.TrimSpace(matches[1])
			value = strings.TrimSuffix(value, "\\")
			var builder strings.Builder
			builder.WriteString(value)
			for i+1 < len(lines) && (strings.HasPrefix(lines[i+1], " ") || strings.HasPrefix(lines[i+1], "\t")) {
				i++
				nextLine := lines[i]
				nextVal := strings.TrimSpace(nextLine)
				nextVal = strings.TrimSuffix(nextVal, "\\")
				builder.WriteString(" " + nextVal)
			}
			fields := strings.Fields(builder.String())
			for _, f := range fields {
				ipnet, err := parseIPOrSubnet(f)
				if err != nil {
					log.Printf("Warning: ignoring invalid IP in ignoreip: %s (%v)", f, err)
					continue
				}
				ips = append(ips, ipnet)
			}
		}
	}
	return ips
}

func sortIPNets(ips []*net.IPNet) {
	sort.Slice(ips, func(i, j int) bool {
		return lessIPNet(ips[i], ips[j])
	})
}

func lessIPNet(a, b *net.IPNet) bool {
	a4 := a.IP.To4() != nil
	b4 := b.IP.To4() != nil
	if a4 && !b4 {
		return true
	}
	if !a4 && b4 {
		return false
	}
	if !a4 && !b4 {
		return a.String() < b.String()
	}
	// Both IPv4
	catA := ipv4Category(a)
	catB := ipv4Category(b)
	if catA != catB {
		return catA < catB
	}
	ipA := ipToUint32(a.IP)
	ipB := ipToUint32(b.IP)
	if ipA != ipB {
		return ipA < ipB
	}
	maskA, _ := a.Mask.Size()
	maskB, _ := b.Mask.Size()
	return maskA > maskB
}

func ipToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}

func ipv4Category(ipnet *net.IPNet) int {
	ip := ipnet.IP.To4()
	if ip == nil {
		return 2
	}
	if ip[0] == 127 {
		return 0
	}
	if ip[0] == 10 ||
		(ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) ||
		(ip[0] == 192 && ip[1] == 168) ||
		(ip[0] == 169 && ip[1] == 254) {
		return 1
	}
	return 2
}

func formatIgnoreIP(ips []*net.IPNet) []string {
	if len(ips) == 0 {
		return nil
	}
	var lines []string

	first := formatIPNet(ips[0])
	if len(ips) > 1 {
		first += " \\"
	}
	lines = append(lines, "ignoreip = "+first)

	for i := 1; i < len(ips)-1; i++ {
		line := formatIPNet(ips[i])
		lines = append(lines, "           "+line+" \\")
	}
	if len(ips) > 1 {
		last := formatIPNet(ips[len(ips)-1])
		lines = append(lines, "           "+last)
	}
	return lines
}

func formatIPNet(ipnet *net.IPNet) string {
	ones, bits := ipnet.Mask.Size()
	if (bits == 32 && ones == 32) || (bits == 128 && ones == 128) {
		return ipnet.IP.String()
	}
	return ipnet.String()
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
