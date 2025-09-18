package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/likexian/whois"
)

type GeoInfo struct {
	Status      string  `json:"status"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Region      string  `json:"region"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	Query       string  `json:"query"`
	Timezone    string  `json:"timezone"`
}

type PortInfo struct {
	Port    int
	Service string
	CVEs    []string
	State   string
}

type WhoisInfo struct {
	Registrar string
	OrgName   string
	Email     string
	Created   string
	Updated   string
}

var (
	ip       = flag.String("ip", "", "IP-адрес или CIDR-подсеть для сканирования")
	ports    = flag.String("ports", "1-1024", "Диапазон портов (например, '1-100', '80,443,8080')")
	workers  = flag.Int("workers", 100, "Количество одновременных горутин")
	timeout  = flag.Int("timeout", 1000, "Тайм-аут в миллисекундах")
	verbose  = flag.Bool("v", false, "Включить подробный вывод прогресса")
	helpFlag = flag.Bool("help", false, "Показать справку")
)

var knownPorts map[int]string

func main() {
	flag.Parse()

	if *helpFlag || *ip == "" {
		showHelp()
		return
	}

	var err error
	knownPorts, err = loadKnownPorts()
	if err != nil {
		fmt.Printf("❌ Ошибка загрузки known_ports.json: %v\n", err)
		return
	}

	fmt.Printf("🕵️‍♂️ Сбор OSINT-данных для IP-адреса: %s\n", *ip)

	geoInfo, err := getGeoInfo(*ip)
	if err != nil {
		fmt.Printf("❌ Ошибка при получении геолокации: %v\n", err)
	} else {
		fmt.Println("\n--- Геолокация ---")
		fmt.Printf("    Страна: %s (%s)\n", geoInfo.Country, geoInfo.CountryCode)
		fmt.Printf("    Город: %s\n", geoInfo.City)
		fmt.Printf("    Провайдер: %s\n", geoInfo.ISP)
		fmt.Printf("    Организация: %s\n", geoInfo.Org)
		fmt.Printf("    Часовой пояс: %s\n", geoInfo.Timezone)
		fmt.Printf("    Координаты: %.4f, %.4f\n", geoInfo.Lat, geoInfo.Lon)
	}

	hostnames, err := net.LookupAddr(*ip)
	fmt.Println("\n--- DNS ---")
	if err != nil || len(hostnames) == 0 {
		fmt.Println("    Обратная DNS-запись не найдена.")
	} else {
		fmt.Printf("    Имя хоста: %s\n", hostnames[0])
	}

	whoisInfo, err := getWhoisInfo(*ip)
	fmt.Println("\n--- WHOIS ---")
	if err != nil {
		fmt.Printf("    WHOIS-информация не найдена или не доступна: %v\n", err)
	} else {
		fmt.Printf("    Регистратор: %s\n", whoisInfo.Registrar)
		fmt.Printf("    Организация: %s\n", whoisInfo.OrgName)
		fmt.Printf("    Email: %s\n", whoisInfo.Email)
		fmt.Printf("    Создан: %s\n", whoisInfo.Created)
		fmt.Printf("    Обновлён: %s\n", whoisInfo.Updated)
	}

	ips, err := getIPsFromCIDR(*ip)
	if err != nil {
		fmt.Printf("\n❌ Ошибка: %v\n", err)
		return
	}

	var allPorts []PortInfo
	for _, targetIP := range ips {
		ports, err := scanTarget(targetIP)
		if err != nil {
			fmt.Printf("Ошибка сканирования %s: %v\n", targetIP, err)
			continue
		}
		allPorts = append(allPorts, ports...)
	}

	if len(allPorts) == 0 {
		fmt.Println("\nОткрытых портов не найдено.")
	} else {
		sort.Slice(allPorts, func(i, j int) bool {
			return allPorts[i].Port < allPorts[j].Port
		})

		fmt.Println("\n--- Результаты сканирования портов ---")
		printPortsByState(allPorts, "open", "✅ Открытые порты")
		printPortsByState(allPorts, "filtered", "🔍 Отфильтрованные порты")
		printPortsByState(allPorts, "closed", "🚫 Закрытые порты (только в режиме -v)")

		outputFile := fmt.Sprintf("scan_results_%s.json", strings.ReplaceAll(time.Now().Format("2006-01-02_15-04-05"), ":", "-"))
		if err := saveResultsToJSON(allPorts, outputFile); err != nil {
			fmt.Printf("Ошибка при сохранении результатов: %v\n", err)
		} else {
			fmt.Printf("\nРезультаты сохранены в файл: %s\n", outputFile)
		}
	}
}

func printPortsByState(ports []PortInfo, state, header string) {
	var relevantPorts []PortInfo
	for _, p := range ports {
		if p.State == state {
			relevantPorts = append(relevantPorts, p)
		}
	}

	if len(relevantPorts) > 0 {
		fmt.Println("\n" + header + ":")
		for _, p := range relevantPorts {
			details := p.Service
			if len(p.CVEs) > 0 {
				details += " (Уязвимости: " + strings.Join(p.CVEs, ", ") + ")"
			}
			fmt.Printf("    Порт %d: %s\n", p.Port, details)
		}
	}
}

func scanTarget(ip string) ([]PortInfo, error) {
	portsToScan := make(chan int, *workers)
	results := make(chan PortInfo, *workers)

	var allPorts []PortInfo
	var collectorWg sync.WaitGroup
	collectorWg.Add(1)
	go func() {
		defer collectorWg.Done()
		for p := range results {
			allPorts = append(allPorts, p)
		}
	}()

	var scannerWg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		scannerWg.Add(1)
		go worker(portsToScan, results, ip, &scannerWg)
	}

	portList, err := parsePorts(*ports)
	if err != nil {
		return nil, err
	}
	for _, p := range portList {
		portsToScan <- p
	}
	close(portsToScan)

	scannerWg.Wait()
	close(results)
	collectorWg.Wait()

	return allPorts, nil
}

func worker(ports <-chan int, results chan<- PortInfo, ip string, wg *sync.WaitGroup) {
	defer wg.Done()
	for p := range ports {
		address := net.JoinHostPort(ip, fmt.Sprint(p))
		conn, err := net.DialTimeout("tcp", address, time.Duration(*timeout)*time.Millisecond)
		if err != nil {
			var opErr *net.OpError
			if errors.As(err, &opErr) && (opErr.Timeout() || strings.Contains(opErr.Error(), "timeout")) {
				results <- PortInfo{Port: p, State: "filtered", Service: "Отфильтрован (таймаут)"}
				if *verbose {
					fmt.Printf("[-] Порт %d отфильтрован\n", p)
				}
			} else if strings.Contains(err.Error(), "connection refused") {
				results <- PortInfo{Port: p, State: "closed", Service: "Закрыт (отказ в соединении)"}
				if *verbose {
					fmt.Printf("[-] Порт %d закрыт\n", p)
				}
			} else {
				results <- PortInfo{Port: p, State: "closed", Service: "Закрыт"}
				if *verbose {
					fmt.Printf("[-] Порт %d закрыт: %s\n", p, err)
				}
			}
			continue
		}

		serviceInfo := getServiceInfo(p, conn)
		conn.Close()

		cves := checkCVEs(serviceInfo)
		results <- PortInfo{Port: p, Service: serviceInfo, CVEs: cves, State: "open"}
		if *verbose {
			fmt.Printf("[+] Порт %d открыт: %s\n", p, serviceInfo)
		}
	}
}

func saveResultsToJSON(results []PortInfo, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}

func getServiceInfo(port int, conn net.Conn) string {
	if service, ok := knownPorts[port]; ok {
		return service
	}

	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		banner := strings.TrimSpace(string(buf[:n]))
		if len(banner) > 50 {
			banner = banner[:50] + "..."
		}
		return strings.ReplaceAll(banner, "\n", " ")
	}

	return "Неизвестный сервис"
}

func checkCVEs(serviceInfo string) []string {
	var foundCVEs []string
	if strings.Contains(serviceInfo, "nginx/1.2") {
		foundCVEs = append(foundCVEs, "CVE-2021-36173 (NGINX HTTP/2-Vulnerability)")
	}
	if strings.Contains(serviceInfo, "VMware Authentication Daemon Version 1.10") {
		foundCVEs = append(foundCVEs, "CVE-2023-34048 (Authentication bypass)")
	}
	return foundCVEs
}

func getGeoInfo(ip string) (*GeoInfo, error) {
	client := resty.New()
	resp, err := client.R().Get(fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,countryCode,region,regionName,city,lat,lon,isp,org,query,timezone", ip))
	if err != nil {
		return nil, err
	}
	var geoInfo GeoInfo
	err = json.Unmarshal(resp.Body(), &geoInfo)
	if err != nil {
		return nil, err
	}
	if geoInfo.Status != "success" {
		return nil, fmt.Errorf("не удалось получить информацию о геолокации. Статус: %s", geoInfo.Status)
	}
	return &geoInfo, nil
}

func getWhoisInfo(query string) (*WhoisInfo, error) {
	whoisData, err := whois.Whois(query)
	if err != nil {
		return nil, err
	}

	var info WhoisInfo
	lines := strings.Split(whoisData, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Registrar:") {
			info.Registrar = strings.TrimSpace(strings.TrimPrefix(line, "Registrar:"))
		}
		if strings.HasPrefix(line, "OrgName:") {
			info.OrgName = strings.TrimSpace(strings.TrimPrefix(line, "OrgName:"))
		}
		if strings.HasPrefix(line, "Registrant Email:") {
			info.Email = strings.TrimSpace(strings.TrimPrefix(line, "Registrant Email:"))
		}
		if strings.HasPrefix(line, "Creation Date:") {
			info.Created = strings.TrimSpace(strings.TrimPrefix(line, "Creation Date:"))
		}
		if strings.HasPrefix(line, "Updated Date:") {
			info.Updated = strings.TrimSpace(strings.TrimPrefix(line, "Updated Date:"))
		}
	}

	if info.Registrar == "" && info.OrgName == "" {
		return nil, errors.New("не удалось найти информацию WHOIS")
	}

	return &info, nil
}

func loadKnownPorts() (map[int]string, error) {
	file, err := os.ReadFile("known_ports.json")
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать файл known_ports.json: %v", err)
	}

	var rawData map[string]string
	if err := json.Unmarshal(file, &rawData); err != nil {
		return nil, fmt.Errorf("ошибка при разборе JSON: %v", err)
	}

	knownPorts := make(map[int]string)
	for portStr, service := range rawData {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("ошибка при преобразовании порта '%s': %v", portStr, err)
		}
		knownPorts[port] = service
	}
	return knownPorts, nil
}

func parsePorts(ports string) ([]int, error) {
	var portList []int
	parts := strings.Split(ports, ",")
	for _, part := range parts {
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			var start, end int
			if _, err := fmt.Sscanf(rangeParts[0], "%d", &start); err != nil {
				return nil, err
			}
			if _, err := fmt.Sscanf(rangeParts[1], "%d", &end); err != nil {
				return nil, err
			}
			for i := start; i <= end; i++ {
				portList = append(portList, i)
			}
		} else {
			var p int
			if _, err := fmt.Sscanf(part, "%d", &p); err != nil {
				return nil, err
			}
			portList = append(portList, p)
		}
	}
	return portList, nil
}

func getIPsFromCIDR(cidr string) ([]string, error) {
	if !strings.Contains(cidr, "/") {
		return []string{cidr}, nil
	}
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	return ips, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func showHelp() {
	fmt.Println("Использование: go run main.go [флаги]")
	fmt.Println("Пример: go run main.go -ip 127.0.0.1 -ports 1-1024 -v")
	fmt.Println("Пример: go run main.go -ip 192.168.1.0/24 -ports 80,443")
	fmt.Println("\nФлаги:")
	flag.PrintDefaults()
}
