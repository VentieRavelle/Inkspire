package osint

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/likexian/whois"
)

type GeoInfo struct {
	Status      string  `json:"status"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	Zip         string  `json:"zip"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Timezone    string  `json:"timezone"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	Query       string  `json:"query"`
}

type ParsedWhois struct {
	Registrar string
	Org       string
	Created   string
	Email     string
}

func GetGeo(ip string) (*GeoInfo, error) {
	client := resty.New().SetTimeout(5 * time.Second)

	resp, err := client.R().Get("http://ip-api.com/json/" + ip + "?fields=66846719")
	if err != nil {
		return nil, err
	}

	var info GeoInfo
	if err := json.Unmarshal(resp.Body(), &info); err != nil {
		return nil, err
	}

	if info.Status != "success" {
		return nil, fmt.Errorf("ip-api error: %s", info.Status)
	}
	return &info, nil
}

func GetWhois(ip string) (*ParsedWhois, error) {
	raw, err := whois.Whois(ip)
	if err != nil {
		return nil, err
	}

	info := &ParsedWhois{}
	lines := strings.Split(raw, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		lowLine := strings.ToLower(line)

		switch {
		case strings.HasPrefix(lowLine, "registrar:"):
			info.Registrar = trimValue(line, "Registrar:")
		case strings.HasPrefix(lowLine, "orgname:") || strings.HasPrefix(lowLine, "organization:"):
			info.Org = trimValue(line, "OrgName:", "Organization:")
		case strings.HasPrefix(lowLine, "creation date:") || strings.HasPrefix(lowLine, "created:"):
			info.Created = trimValue(line, "Creation Date:", "Created:")
		case strings.HasPrefix(lowLine, "registrant email:") || strings.HasPrefix(lowLine, "contact-email:"):
			info.Email = trimValue(line, "Registrant Email:", "Contact-Email:")
		}
	}

	if info.Registrar == "" && info.Org == "" {
		return nil, fmt.Errorf("whois parsing failed or data hidden")
	}

	return info, nil
}

func LookupDNS(ip string) []string {
	names, err := net.LookupAddr(ip)
	if err != nil {
		return []string{"N/A"}
	}
	return names
}

func trimValue(line string, prefixes ...string) string {
	res := line
	for _, p := range prefixes {
		res = strings.TrimPrefix(res, p)
	}
	return strings.TrimSpace(res)
}
