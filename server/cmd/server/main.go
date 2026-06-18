package main

import (
	"log"

	"ManScan/server/internal/app"
)

func main() {
	if err := app.Run(); err != nil {
		log.Fatalf("启动服务失败: %v", err)
	}
}
