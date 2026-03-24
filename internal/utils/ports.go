package utils

import (
	"encoding/json"
	"os"
	"strconv"
)

func LoadKnownPorts(path string) (map[int]string, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var rawData map[string]string
	if err := json.Unmarshal(file, &rawData); err != nil {
		return nil, err
	}

	knownPorts := make(map[int]string)
	for portStr, service := range rawData {
		port, _ := strconv.Atoi(portStr)
		knownPorts[port] = service
	}
	return knownPorts, nil
}
