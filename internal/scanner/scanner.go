package scanner

import (
	"fmt"
	"net"
	"sync"
	"time"
)

type Result struct {
	Port    int
	Proto   string
	State   string
	Service string
}

func Scan(ip string, ports []int, workers int, timeout time.Duration, db map[int]string) []Result {
	tasks := make(chan int, len(ports))
	results := make(chan Result, len(ports)*2)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range tasks {
				results <- scanTCP(ip, p, timeout, db)
				results <- scanUDP(ip, p, timeout, db)
			}
		}()
	}

	for _, p := range ports {
		tasks <- p
	}
	close(tasks)

	wg.Wait()
	close(results)

	var output []Result
	for r := range results {
		if r.State != "closed" {
			output = append(output, r)
		}
	}
	return output
}

func scanTCP(ip string, port int, timeout time.Duration, db map[int]string) Result {
	addr := net.JoinHostPort(ip, fmt.Sprint(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return Result{Port: port, Proto: "tcp", State: "closed"}
	}
	defer conn.Close()

	serviceName := "unknown"
	if name, ok := db[port]; ok {
		serviceName = name
	}

	banner := getBanner(conn)
	if banner != "unknown" {
		serviceName = fmt.Sprintf("%s (%s)", serviceName, banner)
	}

	return Result{Port: port, Proto: "tcp", State: "open", Service: serviceName}
}

func scanUDP(ip string, port int, timeout time.Duration, db map[int]string) Result {
	addr := net.JoinHostPort(ip, fmt.Sprint(port))
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return Result{Port: port, Proto: "udp", State: "closed"}
	}
	defer conn.Close()

	serviceName := "unknown"
	if name, ok := db[port]; ok {
		serviceName = name
	}

	conn.SetDeadline(time.Now().Add(timeout))
	_, _ = conn.Write([]byte("ping"))

	return Result{Port: port, Proto: "udp", State: "open/filtered", Service: serviceName}
}

func getBanner(conn net.Conn) string {
	conn.SetReadDeadline(time.Now().Add(time.Millisecond * 500))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n > 0 {
		return string(buf[:n])
	}
	return "unknown"
}
