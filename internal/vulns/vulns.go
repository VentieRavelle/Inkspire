package vulns

import "strings"

type Vulnerability struct {
	Keyword string
	CVE     string
}

var db = []Vulnerability{
	{"nginx/1.2", "CVE-2021-36173"},
	{"OpenSSH_7.4", "CVE-2017-15906"},
	{"Apache/2.4.41", "CVE-2021-41773"},

	{"OpenSSH_8.9", "CVE-2023-38408 (Remote Code Execution)"},
	{"OpenSSH_9.2", "CVE-2023-38408 (RCE via PKCS#11)"},
	{"OpenSSH_4.4", "CVE-2006-5051 (Signal Handler Race Condition)"},

	{"nginx/1.20.1", "CVE-2021-23017 (DNS Resolver Off-by-one)"},
	{"nginx/1.18.0", "CVE-2021-23017 (Memory Corruption)"},

	{"Apache/2.4.49", "CVE-2021-41773 (Path Traversal & RCE)"},
	{"Apache/2.4.50", "CVE-2021-42013 (Path Traversal Fix Bypass)"},

	{"OpenSSL 3.0.0", "CVE-2022-3786 (X.509 Email Address Buffer Overrun)"},
	{"OpenSSL 1.1.1", "CVE-2023-0286 (Type Confusion in X.509)"},

	{"Redis 6.0", "CVE-2021-32626 (Memory Corruption)"},
	{"Redis 7.0", "CVE-2023-28856 (Potential Deserialization)"},

	{"MySQL 5.7", "CVE-2022-21245 (Oracle Security Update)"},
	{"PostgreSQL 15.0", "CVE-2023-2454 (Case-insensitive Search Vulnerability)"},

	{"Docker 20.10.15", "CVE-2022-24769 (Privilege Escalation)"},
	{"Exim 4.94", "CVE-2021-27216 (Local Privilege Escalation)"},
}

func Check(banner string) []string {
	var found []string
	cleanBanner := strings.ToLower(banner)
	for _, v := range db {
		if strings.Contains(cleanBanner, strings.ToLower(v.Keyword)) {
			found = append(found, v.CVE)
		}
	}
	return found
}
