package handler

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	maxBodyBytes      = 16 * 1024
	maxTurnstileToken = 2048
	turnstileEndpoint = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	contactAction     = "contact"
	rateLimitRequests = 5
	rateLimitWindow   = 10 * time.Minute
	publicError       = "We could not send your inquiry. Please try again."
)

type contactRequest struct {
	Name           string `json:"name"`
	Email          string `json:"email"`
	Phone          string `json:"phone"`
	Message        string `json:"message"`
	Product        string `json:"product"`
	TurnstileToken string `json:"turnstileToken"`
}

type apiResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type turnstileResponse struct {
	Success     bool     `json:"success"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	Action      string   `json:"action"`
	ErrorCodes  []string `json:"error-codes"`
}

type rateEntry struct {
	Count       int
	WindowStart time.Time
}

var (
	rateMu      sync.Mutex
	rateEntries = make(map[string]rateEntry)
	verifyHTTP  = &http.Client{Timeout: 8 * time.Second}
)

func Handler(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)

	allowedHosts := configuredHostnames()
	if len(allowedHosts) == 0 {
		log.Printf("contact: configuration error: no allowed hostname")
		writeJSON(w, http.StatusInternalServerError, false, publicError)
		return
	}

	origin := r.Header.Get("Origin")
	originIsAllowed := originAllowed(origin, allowedHosts)
	if originIsAllowed {
		setCORSHeaders(w, origin)
	}
	if r.Method != http.MethodPost && r.Method != http.MethodOptions {
		w.Header().Set("Allow", http.MethodPost+", "+http.MethodOptions)
		writeJSON(w, http.StatusMethodNotAllowed, false, publicError)
		return
	}
	if !originIsAllowed {
		log.Printf("contact: rejected request origin")
		writeJSON(w, http.StatusBadRequest, false, publicError)
		return
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	clientIP := requestIP(r)
	if !allowRequest(clientIP, time.Now()) {
		w.Header().Set("Retry-After", strconv.Itoa(int(rateLimitWindow.Seconds())))
		writeJSON(w, http.StatusTooManyRequests, false, "Too many requests. Please wait before trying again.")
		return
	}

	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeJSON(w, http.StatusBadRequest, false, publicError)
		return
	}

	body := http.MaxBytesReader(w, r.Body, maxBodyBytes)
	defer body.Close()
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()

	var input contactRequest
	if err := decoder.Decode(&input); err != nil {
		if isTooLarge(err) {
			writeJSON(w, http.StatusRequestEntityTooLarge, false, publicError)
			return
		}
		writeJSON(w, http.StatusBadRequest, false, publicError)
		return
	}
	if err := ensureJSONEnd(decoder); err != nil {
		if isTooLarge(err) {
			writeJSON(w, http.StatusRequestEntityTooLarge, false, publicError)
			return
		}
		writeJSON(w, http.StatusBadRequest, false, publicError)
		return
	}

	input.normalize()
	if err := input.validate(); err != nil {
		log.Printf("contact: validation rejected: %s", err)
		writeJSON(w, http.StatusBadRequest, false, publicError)
		return
	}

	valid, err := verifyTurnstile(r.Context(), input.TurnstileToken, clientIP, allowedHosts)
	if err != nil {
		log.Printf("contact: turnstile service error: %v", err)
		writeJSON(w, http.StatusInternalServerError, false, publicError)
		return
	}
	if !valid {
		log.Printf("contact: turnstile rejected")
		writeJSON(w, http.StatusBadRequest, false, publicError)
		return
	}

	if err := sendEmail(r.Context(), input); err != nil {
		log.Printf("contact: smtp delivery failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, false, publicError)
		return
	}

	writeJSON(w, http.StatusOK, true, "Your inquiry has been sent successfully.")
}

func (c *contactRequest) normalize() {
	c.Name = strings.TrimSpace(c.Name)
	c.Email = strings.TrimSpace(c.Email)
	c.Phone = strings.TrimSpace(c.Phone)
	c.Message = strings.TrimSpace(c.Message)
	c.Product = strings.TrimSpace(c.Product)
	c.TurnstileToken = strings.TrimSpace(c.TurnstileToken)
}

func (c contactRequest) validate() error {
	if !runeLength(c.Name, 2, 80) {
		return errors.New("invalid name")
	}
	if utf8.RuneCountInString(c.Email) > 254 || strings.ContainsAny(c.Email, "\r\n") {
		return errors.New("invalid email")
	}
	address, err := mail.ParseAddress(c.Email)
	if err != nil || address.Address != c.Email || !strings.Contains(address.Address, "@") {
		return errors.New("invalid email")
	}
	if utf8.RuneCountInString(c.Phone) > 40 || strings.ContainsAny(c.Phone, "\r\n") {
		return errors.New("invalid phone")
	}
	if !runeLength(c.Message, 10, 2000) {
		return errors.New("invalid message")
	}
	if utf8.RuneCountInString(c.Product) > 150 || strings.ContainsAny(c.Product, "\r\n") {
		return errors.New("invalid product")
	}
	if c.TurnstileToken == "" || len(c.TurnstileToken) > maxTurnstileToken {
		return errors.New("invalid turnstile token")
	}
	return nil
}

func runeLength(value string, min, max int) bool {
	length := utf8.RuneCountInString(value)
	return length >= min && length <= max
}

func ensureJSONEnd(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values")
	}
	return err
}

func isTooLarge(err error) bool {
	var maxErr *http.MaxBytesError
	return errors.As(err, &maxErr)
}

func configuredHostnames() map[string]struct{} {
	hosts := make(map[string]struct{})
	for _, raw := range strings.Split(os.Getenv("TURNSTILE_ALLOWED_HOSTNAME"), ",") {
		if host := normalizeHostname(raw); host != "" {
			hosts[host] = struct{}{}
		}
	}
	if previewHost := normalizeHostname(os.Getenv("VERCEL_URL")); previewHost != "" {
		hosts[previewHost] = struct{}{}
	}
	return hosts
}

func normalizeHostname(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "https://")
	value = strings.TrimPrefix(value, "http://")
	value = strings.TrimSuffix(value, "/")
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	return strings.TrimSuffix(value, ".")
}

func originAllowed(origin string, hosts map[string]struct{}) bool {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	host := normalizeHostname(parsed.Hostname())
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && (host == "localhost" || host == "127.0.0.1")) {
		return false
	}
	if _, ok := hosts[host]; !ok {
		return false
	}

	configured := strings.TrimSpace(os.Getenv("CONTACT_ALLOWED_ORIGINS"))
	if configured == "" {
		return true
	}
	normalizedOrigin := strings.TrimSuffix(strings.ToLower(origin), "/")
	for _, candidate := range strings.Split(configured, ",") {
		if normalizedOrigin == strings.TrimSuffix(strings.ToLower(strings.TrimSpace(candidate)), "/") {
			return true
		}
	}
	return false
}

func requestIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func allowRequest(key string, now time.Time) bool {
	if key == "" {
		key = "unknown"
	}
	rateMu.Lock()
	defer rateMu.Unlock()

	entry, exists := rateEntries[key]
	if !exists || now.Sub(entry.WindowStart) >= rateLimitWindow {
		rateEntries[key] = rateEntry{Count: 1, WindowStart: now}
		return true
	}
	if entry.Count >= rateLimitRequests {
		return false
	}
	entry.Count++
	rateEntries[key] = entry

	if len(rateEntries) > 1000 {
		for ip, candidate := range rateEntries {
			if now.Sub(candidate.WindowStart) >= rateLimitWindow {
				delete(rateEntries, ip)
			}
		}
	}
	return true
}

func verifyTurnstile(ctx context.Context, token, remoteIP string, allowedHosts map[string]struct{}) (bool, error) {
	secret := strings.TrimSpace(os.Getenv("TURNSTILE_SECRET_KEY"))
	if secret == "" {
		return false, errors.New("TURNSTILE_SECRET_KEY is not configured")
	}

	form := url.Values{
		"secret":   {secret},
		"response": {token},
	}
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, turnstileEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return false, fmt.Errorf("create verification request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := verifyHTTP.Do(req)
	if err != nil {
		return false, fmt.Errorf("verify token: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return false, fmt.Errorf("verification returned status %d", response.StatusCode)
	}

	var result turnstileResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 16*1024)).Decode(&result); err != nil {
		return false, fmt.Errorf("decode verification: %w", err)
	}
	if !result.Success {
		return false, nil
	}
	if _, ok := allowedHosts[normalizeHostname(result.Hostname)]; !ok {
		return false, nil
	}
	if result.Action != contactAction {
		return false, nil
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, result.ChallengeTS)
	if err != nil {
		return false, nil
	}
	age := time.Since(issuedAt)
	if age < -time.Minute || age > 5*time.Minute {
		return false, nil
	}
	return true, nil
}

func sendEmail(ctx context.Context, input contactRequest) error {
	host := strings.TrimSpace(os.Getenv("MAILBUX_SMTP_HOST"))
	port := strings.TrimSpace(os.Getenv("MAILBUX_SMTP_PORT"))
	username := strings.TrimSpace(os.Getenv("MAILBUX_SMTP_USER"))
	password := os.Getenv("MAILBUX_SMTP_PASS")
	recipient := strings.TrimSpace(os.Getenv("CONTACT_EMAIL"))
	if host == "" || port == "" || username == "" || password == "" || recipient == "" {
		return errors.New("SMTP configuration is incomplete")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return errors.New("SMTP port is invalid")
	}
	if _, err := mail.ParseAddress(username); err != nil {
		return errors.New("SMTP user address is invalid")
	}
	if _, err := mail.ParseAddress(recipient); err != nil {
		return errors.New("contact address is invalid")
	}

	address := net.JoinHostPort(host, port)
	dialer := net.Dialer{Timeout: 8 * time.Second}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return fmt.Errorf("connect to SMTP server: %w", err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return fmt.Errorf("set SMTP deadline: %w", err)
	}

	client, err := smtp.NewClient(connection, host)
	if err != nil {
		return fmt.Errorf("start SMTP client: %w", err)
	}
	defer client.Close()

	if ok, _ := client.Extension("STARTTLS"); !ok {
		return errors.New("SMTP server does not support STARTTLS")
	}
	if err := client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
		return fmt.Errorf("start TLS: %w", err)
	}
	if ok, _ := client.Extension("AUTH"); !ok {
		return errors.New("SMTP server does not support authentication")
	}
	if err := client.Auth(smtp.PlainAuth("", username, password, host)); err != nil {
		return fmt.Errorf("authenticate SMTP: %w", err)
	}
	if err := client.Mail(username); err != nil {
		return fmt.Errorf("set sender: %w", err)
	}
	if err := client.Rcpt(recipient); err != nil {
		return fmt.Errorf("set recipient: %w", err)
	}

	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("open message writer: %w", err)
	}
	if _, err := writer.Write(buildMessage(input, username, recipient)); err != nil {
		writer.Close()
		return fmt.Errorf("write message: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("close message: %w", err)
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("finish SMTP session: %w", err)
	}
	return nil
}

func buildMessage(input contactRequest, sender, recipient string) []byte {
	product := input.Product
	if product == "" {
		product = "General Inquiry"
	}
	subject := mime.QEncoding.Encode("UTF-8", "New Website Inquiry — "+product)

	var message strings.Builder
	fmt.Fprintf(&message, "From: Rupa Silverworks Website <%s>\r\n", sender)
	fmt.Fprintf(&message, "To: %s\r\n", recipient)
	fmt.Fprintf(&message, "Reply-To: %s\r\n", input.Email)
	fmt.Fprintf(&message, "Subject: %s\r\n", subject)
	message.WriteString("MIME-Version: 1.0\r\n")
	message.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	message.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
	message.WriteString("\r\n")

	plainBody := fmt.Sprintf("New website inquiry\n\nName: %s\nEmail: %s\nPhone: %s\nProduct: %s\n\nMessage:\n%s\n", input.Name, input.Email, valueOrDash(input.Phone), valueOrDash(input.Product), input.Message)
	encoded := new(strings.Builder)
	quoted := quotedprintable.NewWriter(encoded)
	_, _ = quoted.Write([]byte(plainBody))
	_ = quoted.Close()
	message.WriteString(encoded.String())
	return []byte(message.String())
}

func valueOrDash(value string) string {
	if value == "" {
		return "—"
	}
	return value
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
}

func setCORSHeaders(w http.ResponseWriter, origin string) {
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Methods", http.MethodPost+", "+http.MethodOptions)
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Max-Age", "600")
	w.Header().Add("Vary", "Origin")
}

func writeJSON(w http.ResponseWriter, status int, success bool, message string) {
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(apiResponse{Success: success, Message: message}); err != nil {
		log.Printf("contact: response encoding failed: %v", err)
	}
}
