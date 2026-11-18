package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"strings"
	"time"
)

func wyslijMaila(do, temat, tresc string) error {
	if cs := env("ACS_CONNECTION_STRING", ""); cs != "" {
		return wyslijPrzezACS(cs, env("EMAIL_SENDER", ""), do, temat, tresc)
	}
	return wyslijPrzezSMTP(do, temat, tresc)
}

func wyslijPrzezACS(connStr, od, do, temat, tresc string) error {
	var endpoint, klucz string
	for _, czesc := range strings.Split(connStr, ";") {
		if k, v, ok := strings.Cut(czesc, "="); ok {
			switch strings.ToLower(k) {
			case "endpoint":
				endpoint = strings.TrimSuffix(v, "/")
			case "accesskey":
				klucz = v
			}
		}
	}
	if endpoint == "" || klucz == "" || od == "" {
		return fmt.Errorf("brak endpoint/accesskey w ACS_CONNECTION_STRING lub brak EMAIL_SENDER")
	}

	cialo, err := json.Marshal(map[string]any{
		"senderAddress": od,
		"recipients": map[string]any{
			"to": []map[string]string{{"address": do}},
		},
		"content": map[string]string{
			"subject":   temat,
			"plainText": tresc,
		},
	})
	if err != nil {
		return err
	}

	u, err := url.Parse(endpoint + "/emails:send?api-version=2023-03-31")
	if err != nil {
		return err
	}

	data := time.Now().UTC().Format(http.TimeFormat)
	hash := sha256.Sum256(cialo)
	hashB64 := base64.StdEncoding.EncodeToString(hash[:])

	doPodpisu := "POST\n" + u.RequestURI() + "\n" + data + ";" + u.Host + ";" + hashB64
	kluczBajty, err := base64.StdEncoding.DecodeString(klucz)
	if err != nil {
		return fmt.Errorf("niepoprawny accesskey: %w", err)
	}
	mac := hmac.New(sha256.New, kluczBajty)
	mac.Write([]byte(doPodpisu))
	podpis := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequest("POST", u.String(), bytes.NewReader(cialo))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-ms-date", data)
	req.Header.Set("x-ms-content-sha256", hashB64)
	req.Header.Set("Authorization",
		"HMAC-SHA256 SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature="+podpis)

	klient := &http.Client{Timeout: 15 * time.Second}
	resp, err := klient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("ACS zwrócił %d: %s", resp.StatusCode, string(b))
	}
	return nil
}


func wyslijPrzezSMTP(do, temat, tresc string) error {
	serwer := env("SMTP_ADRES", "localhost:1025")
	od := env("SMTP_OD", "czat@localhost")

	wiadomosc := "From: " + od + "\r\n" +
		"To: " + do + "\r\n" +
		"Subject: " + mime.QEncoding.Encode("utf-8", temat) + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: 8bit\r\n" +
		"\r\n" +
		strings.ReplaceAll(tresc, "\n", "\r\n")

	var auth smtp.Auth
	if login := env("SMTP_LOGIN", ""); login != "" {
		host, _, _ := net.SplitHostPort(serwer)
		auth = smtp.PlainAuth("", login, env("SMTP_HASLO", ""), host)
	}
	return smtp.SendMail(serwer, auth, od, []string{do}, []byte(wiadomosc))
}