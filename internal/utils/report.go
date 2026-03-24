package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func SaveReport(data interface{}, targetIP string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	downloadDir := filepath.Join(home, "Downloads")

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	fileName := fmt.Sprintf("Inkspire_%s_%s.json", targetIP, timestamp)
	filePath := filepath.Join(downloadDir, fileName)

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	fmt.Printf("\n💾 Отчет сохранен: %s\n", filePath)
	return encoder.Encode(data)
}
