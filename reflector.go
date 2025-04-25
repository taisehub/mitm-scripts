package main

import (
	"bytes"
	"compress/gzip"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
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

	initializeDBPath(*domain)

	for {
		job, err := getJobFromDB()
		if err != nil {
			log.Println("No job found or DB error:", err)
			time.Sleep(2 * time.Second)
			continue
		}

		if err := deleteJobFromDB(job.ID); err != nil {
			log.Println("Error deleting job from DB:", err)
		}

		log.Printf("Scanning: https://%s%s?%s\n", job.Req.Host, job.Req.Path, job.Req.Query)
		if err := scanRequest(job.Req); err != nil {
			log.Println("Error scanning request:", err)
		}
	}
}

func initializeDBPath(domain string) {
	safeName := strings.ReplaceAll(domain, ".", "_")
	dbPath = fmt.Sprintf("/tmp/scan_jobs_%s.db", safeName)

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		log.Fatalf("DB file does not exist: %v\n", dbPath)
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

	return &Job{ID: id, Req: req}, nil
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
	if err := checkReflectionInQueryParams(req); err != nil {
		return err
	}
	return checkReflectionInCookies(req)
}

func checkReflectionInQueryParams(req *Request) error {
	queryParams, err := url.ParseQuery(req.Query)
	if err != nil {
		return err
	}

	// Create a buffered channel to limit concurrency to 5
	concurrencyLimit := 5
	sem := make(chan struct{}, concurrencyLimit)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstError error

	for key := range queryParams {
		wg.Add(1)
		sem <- struct{}{} // Acquire a slot in the semaphore

		go func(key string) {
			defer wg.Done()
			defer func() { <-sem }() // Release the slot when done

			modifiedReq := modifyQueryParam(req, queryParams, key)
			if err := sendRequestAndCheckReflection(&modifiedReq, key); err != nil {
				mu.Lock()
				if firstError == nil {
					firstError = err
				}
				mu.Unlock()
			}
		}(key)
	}

	wg.Wait() // Wait for all goroutines to finish
	return firstError
}

func modifyQueryParam(req *Request, queryParams url.Values, key string) Request {
	modifiedQuery := url.Values{}
	for k, v := range queryParams {
		if k == key {
			modified := appendCanaryToValues(v)
			modifiedQuery[k] = modified
		} else {
			modifiedQuery[k] = v
		}
	}

	modifiedReq := *req
	modifiedReq.Query = modifiedQuery.Encode()
	return modifiedReq
}

func appendCanaryToValues(values []string) []string {
	modified := make([]string, len(values))
	for i, val := range values {
		modified[i] = val + canary + `'"<>`
	}
	return modified
}

func checkReflectionInCookies(req *Request) error {
	cookieHeader, ok := req.Headers["Cookie"]
	if !ok {
		return nil
	}

	cookies := parseCookies(cookieHeader)

	// Create a buffered channel to limit concurrency to 5
	concurrencyLimit := 5
	sem := make(chan struct{}, concurrencyLimit)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstError error

	for key := range cookies {
		wg.Add(1)
		sem <- struct{}{} // Acquire a slot in the semaphore

		go func(key string) {
			defer wg.Done()
			defer func() { <-sem }() // Release the slot when done

			modifiedReq := modifyCookies(req, cookies, key)
			if err := sendRequestAndCheckReflection(&modifiedReq, key); err != nil {
				mu.Lock()
				if firstError == nil {
					firstError = err // Capture the first error
				}
				mu.Unlock()
			}
		}(key)
	}

	wg.Wait() // Wait for all goroutines to finish
	return firstError
}

func modifyCookies(req *Request, cookies map[string]string, key string) Request {
	modifiedCookies := make(map[string]string)
	for k, v := range cookies {
		if k == key {
			modifiedCookies[k] = v + canary + `'"<>`
		} else {
			modifiedCookies[k] = v
		}
	}

	modifiedReq := *req
	modifiedReq.Headers = cloneHeadersWithModifiedCookies(req.Headers, modifiedCookies)
	return modifiedReq
}

func cloneHeadersWithModifiedCookies(headers map[string]string, modifiedCookies map[string]string) map[string]string {
	clonedHeaders := make(map[string]string)
	for hk, hv := range headers {
		if strings.ToLower(hk) == "cookie" {
			clonedHeaders[hk] = formatCookies(modifiedCookies)
		} else {
			clonedHeaders[hk] = hv
		}
	}
	return clonedHeaders
}

func formatCookies(cookies map[string]string) string {
	var cookieParts []string
	for k, v := range cookies {
		cookieParts = append(cookieParts, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(cookieParts, "; ")
}

func sendRequestAndCheckReflection(req *Request, testingParam string) error {
	// Create a custom HTTP client that does not follow redirects
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Prevent following redirects
			return http.ErrUseLastResponse
		},
	}

	fullURL := "https://" + req.Host + req.Path

	request, err := http.NewRequest(req.Method, fullURL, nil)
	if err != nil {
		return err
	}
	request.URL.RawQuery = req.Query

	for key, value := range req.Headers {
		request.Header.Set(key, value)
	}

	resp, err := client.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Detect vulnerabilities
	vulnType := detect(request, resp, testingParam)
	if vulnType != "" {
		dumpRequest(resp, fmt.Sprintf("%s (Type: %s)", testingParam, vulnType)) // Include vulnerability type in dump
	}
	return nil
}

func detect(req *http.Request, resp *http.Response, testingParam string) string {
	// Check for redirect vulnerabilities
	if isRedirect(resp.StatusCode) {
		location := resp.Header.Get("Location")
		if location != "" {
			// Check if the testing parameter is in query parameters
			paramValue := req.URL.Query().Get(testingParam)
			if paramValue != "" && strings.Contains(location, paramValue) {
				return "Open Redirect"
			}

			// Check if the testing parameter is in cookies
			cookieValue := extractCookieValue(req.Cookies(), testingParam)
			if cookieValue != "" && strings.Contains(location, cookieValue) {
				return "Open Redirect (Cookie)"
			}
		}
	}

	// Check for reflection in headers or body
	if isReflected(resp, canary) {
		return "Reflection"
	}

	if resp.StatusCode == 500 {
		return "Server Error"
	}

	return "" // No vulnerability detected
}

func extractCookieValue(cookies []*http.Cookie, cookieName string) string {
	// Extract the value of the specified cookie
	for _, cookie := range cookies {
		if cookie.Name == cookieName {
			return cookie.Value
		}
	}
	return ""
}

func isRedirect(statusCode int) bool {
	// Check if the status code indicates a redirect
	return statusCode == 301 || statusCode == 302 || statusCode == 303 || statusCode == 307 || statusCode == 308
}

func isReflected(resp *http.Response, canary string) bool {
	if containsCanaryInHeaders(resp.Header, canary) {
		return true
	}

	body, err := readResponseBody(resp)
	if err != nil {
		return false
	}

	return strings.Contains(string(body), canary)
}

func containsCanaryInHeaders(headers http.Header, canary string) bool {
	for key, values := range headers {
		for _, val := range values {
			if strings.Contains(val, canary) {
				fmt.Printf("Canary found in header: %s: %s\n", key, val)
				return true
			}
		}
	}
	return false
}

func readResponseBody(resp *http.Response) ([]byte, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if isGzipEncoded(body) {
		return decompressGzip(body)
	}
	return body, nil
}

func isGzipEncoded(body []byte) bool {
	return len(body) >= 2 && body[0] == 31 && body[1] == 139
}

func decompressGzip(body []byte) ([]byte, error) {
	gzipReader, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		fmt.Println("Failed to create gzip reader:", err)
		return nil, err
	}
	defer gzipReader.Close()

	return io.ReadAll(gzipReader)
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

func dumpRequest(resp *http.Response, testingParam string) {
	message := fmt.Sprintf("Detection : %s", testingParam)
	fmt.Println(message)
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
	content := fmt.Sprintf("%s\n%s=======================================\n", message, rawRequest.String())
	f.WriteString(content)
}
