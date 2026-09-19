package handler

import (
	"strings"
	"testing"
	"time"
)

func validContact() contactRequest {
	return contactRequest{
		Name:           "Buyer Name",
		Email:          "buyer@example.com",
		Phone:          "+61 123 456 789",
		Message:        "I am interested in your silver collection.",
		Product:        "Celuk Heritage Ring",
		TurnstileToken: "valid-token",
	}
}

func TestContactValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*contactRequest)
		valid  bool
	}{
		{name: "valid", mutate: func(*contactRequest) {}, valid: true},
		{name: "short name", mutate: func(c *contactRequest) { c.Name = "A" }},
		{name: "bad email", mutate: func(c *contactRequest) { c.Email = "not-an-email" }},
		{name: "header injection", mutate: func(c *contactRequest) { c.Email = "buyer@example.com\r\nBcc: attacker@example.com" }},
		{name: "long phone", mutate: func(c *contactRequest) { c.Phone = strings.Repeat("1", 41) }},
		{name: "short message", mutate: func(c *contactRequest) { c.Message = "too short" }},
		{name: "long product", mutate: func(c *contactRequest) { c.Product = strings.Repeat("x", 151) }},
		{name: "missing token", mutate: func(c *contactRequest) { c.TurnstileToken = "" }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validContact()
			test.mutate(&input)
			if got := input.validate() == nil; got != test.valid {
				t.Fatalf("validate() validity = %v, want %v", got, test.valid)
			}
		})
	}
}

func TestOriginAllowed(t *testing.T) {
	t.Setenv("CONTACT_ALLOWED_ORIGINS", "https://www.rupasilverworks.com")
	hosts := map[string]struct{}{"www.rupasilverworks.com": {}}
	if !originAllowed("https://www.rupasilverworks.com", hosts) {
		t.Fatal("expected production origin to be allowed")
	}
	for _, origin := range []string{"", "null", "http://www.rupasilverworks.com", "https://evil.example", "https://www.rupasilverworks.com.evil.example"} {
		if originAllowed(origin, hosts) {
			t.Fatalf("expected origin %q to be rejected", origin)
		}
	}
}

func TestRateLimit(t *testing.T) {
	rateMu.Lock()
	rateEntries = make(map[string]rateEntry)
	rateMu.Unlock()
	now := time.Now()
	for i := 0; i < rateLimitRequests; i++ {
		if !allowRequest("192.0.2.1", now) {
			t.Fatalf("request %d was unexpectedly rejected", i+1)
		}
	}
	if allowRequest("192.0.2.1", now) {
		t.Fatal("expected request over the limit to be rejected")
	}
	if !allowRequest("192.0.2.1", now.Add(rateLimitWindow)) {
		t.Fatal("expected request after the window to be allowed")
	}
}

func TestMessageHeaders(t *testing.T) {
	message := string(buildMessage(validContact(), "website@rupasilverworks.com", "sales@rupasilverworks.com"))
	for _, expected := range []string{
		"From: Rupa Silverworks Website <website@rupasilverworks.com>",
		"To: sales@rupasilverworks.com",
		"Reply-To: buyer@example.com",
		"Content-Transfer-Encoding: quoted-printable",
	} {
		if !strings.Contains(message, expected) {
			t.Fatalf("message does not contain %q", expected)
		}
	}
}

func TestOfficialTurnstileTestSecrets(t *testing.T) {
	for _, secret := range []string{testSecretPass, testSecretFail, testSecretSpent} {
		if !isOfficialTurnstileTestSecret(secret) {
			t.Fatal("expected official test secret to be recognized")
		}
	}
	if isOfficialTurnstileTestSecret("production-secret") {
		t.Fatal("production secret must not be recognized as a test secret")
	}
}

func TestTurnstileTestSecretAllowsMissingHostnameAndAction(t *testing.T) {
	now := time.Now()
	result := turnstileResponse{
		Success:     true,
		ChallengeTS: now.Format(time.RFC3339Nano),
	}
	hosts := map[string]struct{}{"localhost": {}}

	if !turnstileResponseIsValid(result, testSecretPass, hosts, now) {
		t.Fatal("official test secret should allow missing hostname and action")
	}
	if turnstileResponseIsValid(result, "production-secret", hosts, now) {
		t.Fatal("production secret must reject missing hostname and action")
	}

	result.Hostname = "localhost"
	result.Action = contactAction
	if !turnstileResponseIsValid(result, "production-secret", hosts, now) {
		t.Fatal("production secret should accept matching hostname and action")
	}

	result.ChallengeTS = now.Add(-6 * time.Minute).Format(time.RFC3339Nano)
	if turnstileResponseIsValid(result, testSecretPass, hosts, now) {
		t.Fatal("test secret must still reject expired challenges")
	}
}
