package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func wyslijMaila(do, temat, tresc string) error {
	var endpoint, key string
	for _, p := range strings.Split(env("ACS_CONNECTION_STRING", ""), ";") {
		if v, ok := strings.CutPrefix(p, "endpoint="); ok {
			endpoint = strings.TrimSuffix(v, "/")
		}
		if v, ok := strings.CutPrefix(p, "accesskey="); ok {
			key = v
		}
	}
	if endpoint == "" || key == "" {
		return fmt.Errorf("brak ACS_CONNECTION_STRING")
	}
	host := strings.TrimPrefix(endpoint, "https://")

	payload, _ := json.Marshal(map[string]any{
		"senderAddress": env("EMAIL_SENDER", ""),
		"content":       map[string]string{"subject": temat, "plainText": tresc},
		"recipients":    map[string]any{"to": []map[string]string{{"address": do}}},
	})

	sum := sha256.Sum256(payload)
	contentHash := base64.StdEncoding.EncodeToString(sum[:])
	date := time.Now().UTC().Format(http.TimeFormat)
	path := "/emails:send?api-version=2023-03-31"

	k, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, k)
	mac.Write([]byte("POST\n" + path + "\n" + date + ";" + host + ";" + contentHash))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	req, _ := http.NewRequest("POST", endpoint+path, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-ms-date", date)
	req.Header.Set("x-ms-content-sha256", contentHash)
	req.Header.Set("Authorization",
		"HMAC-SHA256 SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature="+sig)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("acs email: status %d: %s", resp.StatusCode, b)
	}
	return nil
}
