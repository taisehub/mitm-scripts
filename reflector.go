package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"flag"

	_ "github.com/mattn/go-sqlite3"
)

const (
	canary = "kensakensakensakensa"
)

type Request struct {
	Method  string
	Host    string
	Port    string
	Path    string
	Query   string
	Headers map[string]string
	Body    string
}

type Job struct {
	ID  int
	Req *Request
}

var dbPath string

func main() {
	domain := flag.String("domain", "", "Target domain for reflection scanning (e.g., facebook.com)")
	flag.Parse()

	if *domain == "" {
		log.Fatal("Domain must be specified with -domain")
	}

	safeName := strings.ReplaceAll(*domain, ".", "_")
	dbPath = fmt.Sprintf("/tmp/scan_jobs_%s.db", safeName)

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		log.Fatalf("DB file does not exist: %v\n", dbPath)
	}

	for {
		job, err := getJobFromDB()
		if err != nil {
			log.Println("No job found or DB error:", err)
			time.Sleep(2 * time.Second) // ジョブがない場合は2秒待機
			continue
		}

		if err := deleteJobFromDB(job.ID); err != nil {
			log.Println("Error deleting job from DB:", err)
		}

		if err := scanRequest(job.Req); err != nil {
			log.Println("Error scanning request:", err)
			continue
		}

	}
}

func getJobFromDB() (*Job, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var id int
	var method, host, port, path, query, headers, body string
	err = db.QueryRow("SELECT id, method, host, port, path, query, headers, body FROM jobs WHERE status = 'queued' LIMIT 1").Scan(
		&id, &method, &host, &port, &path, &query, &headers, &body,
	)

	if err != nil {
		return nil, err
	}

	req := &Request{
		Method:  method,
		Host:    host,
		Port:    port,
		Path:    path,
		Query:   query,
		Headers: parseHeaders(headers),
		Body:    body,
	}

	return &Job{
		ID:  id,
		Req: req,
	}, nil
}

func deleteJobFromDB(jobID int) error {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.Exec("DELETE FROM jobs WHERE id = ?", jobID)
	return err
}

func scanRequest(req *Request) error {
	queryParams, err := url.ParseQuery(req.Query)
	if err != nil {
		return err
	}

	// check reflection in query params
	for key := range queryParams {
		modifiedQuery := url.Values{}

		for k, v := range queryParams {
			if k == key {
				modified := make([]string, len(v))
				for i, val := range v {
					modified[i] = val + canary + `'"<>`
				}
				modifiedQuery[k] = modified
			} else {
				modifiedQuery[k] = v
			}
		}

		modifiedReq := *req
		modifiedReq.Query = modifiedQuery.Encode()

		err := sendRequestAndCheckReflection(&modifiedReq)
		if err != nil {
			return err
		}
	}

	// check reflection in cookie values
	cookieHeader, ok := req.Headers["Cookie"]
	if ok {
		cookies := parseCookies(cookieHeader)

		for key := range cookies {
			modifiedCookies := make(map[string]string)
			for k, v := range cookies {
				if k == key {
					modifiedCookies[k] = v + canary + `'"<>`
				} else {
					modifiedCookies[k] = v
				}
			}

			modifiedReq := *req
			modifiedReq.Headers = make(map[string]string)
			for hk, hv := range req.Headers {
				if strings.ToLower(hk) == "cookie" {
					var cookieParts []string
					for ck, cv := range modifiedCookies {
						cookieParts = append(cookieParts, fmt.Sprintf("%s=%s", ck, cv))
					}
					modifiedReq.Headers[hk] = strings.Join(cookieParts, "; ")
				} else {
					modifiedReq.Headers[hk] = hv
				}
			}

			err := sendRequestAndCheckReflection(&modifiedReq)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func sendRequestAndCheckReflection(req *Request) error {
	client := &http.Client{}

	fullURL := "https://" + req.Host + req.Path
	request, err := http.NewRequest(req.Method, fullURL, nil)
	if err != nil {
		return err
	}

	request.URL.RawQuery = req.Query

	for key, value := range req.Headers {
		request.Header.Set(key, value)
	}

	proxyURL, _ := url.Parse("http://localhost:8080")
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}
	client.Transport = transport

	resp, err := client.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if isReflected(resp, canary) {
		dumpreq(resp)
	}
	return nil
}

func isReflected(resp *http.Response, canary string) bool {
	for key, values := range resp.Header {
		for _, val := range values {
			if strings.Contains(val, canary) {
				fmt.Printf("Canary found in header: %s: %s\n", key, val)
				return true
			}
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	if strings.Contains(string(body), canary) {
		return true
	}

	return false
}

func parseHeaders(headers string) map[string]string {
	var result map[string]string
	json.Unmarshal([]byte(headers), &result)
	return result
}

func parseCookies(cookies string) map[string]string {
	result := make(map[string]string)
	lines := strings.Split(cookies, ";")
	for _, line := range lines {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			result[parts[0]] = parts[1]
		}
	}
	return result
}

func dumpreq(resp *http.Response) {
	f, err := os.OpenFile("information.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	url := resp.Request.URL
	method := resp.Request.Method
	req := resp.Request

	var rawRequest strings.Builder
	rawRequest.WriteString(fmt.Sprintf("%s %s %s\r\n", method, url.RequestURI(), "HTTP/1.1"))

	for key, values := range req.Header {
		for _, val := range values {
			rawRequest.WriteString(fmt.Sprintf("%s: %s\r\n", key, val))
		}
	}

	rawRequest.WriteString("\r\n")

	content := fmt.Sprintf("%s=======================================\n", rawRequest.String())
	f.WriteString(content)
}
