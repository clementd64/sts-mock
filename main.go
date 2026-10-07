package main

import (
	"context"
	"encoding/xml"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"time"
	"uuid"

	"github.com/coreos/go-oidc/v3/oidc"
)

const stsNamespace = "https://sts.amazonaws.com/doc/2011-06-15/"

func writeError(w http.ResponseWriter, status int, code, message, typ string) {
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.WriteHeader(status)
	_ = xml.NewEncoder(w).Encode(errorResponse{
		XMLNS:     stsNamespace,
		Error:     apiError{Type: typ, Code: code, Message: message},
		RequestID: uuid.NewV7().String(),
	})
}

func run() error {
	addr := flag.String("addr", ":8080", "address on which to listen")
	issuerURL := flag.String("issuer-url", "", "OIDC issuer URL")
	audience := flag.String("audience", "", "JWT audience")
	accessKeyID := flag.String("access-key-id", "", "AWS access key ID")
	secretAccessKey := flag.String("secret-access-key", "", "AWS secret access key")
	flag.Parse()

	provider, err := oidc.NewProvider(context.Background(), *issuerURL)
	if err != nil {
		return err
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: *audience})

	slog.Info("sts-mock listening", "addr", *addr)
	return http.ListenAndServe(*addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "InvalidAction", "only GET and POST are supported", "Sender")
			return
		}

		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusBadRequest, "ValidationError", "invalid form parameters", "Sender")
			return
		}

		if r.Form.Get("Action") != "AssumeRoleWithWebIdentity" {
			writeError(w, http.StatusBadRequest, "InvalidAction", "unsupported Action", "Sender")
			return
		}

		claims, err := verifier.Verify(r.Context(), r.Form.Get("WebIdentityToken"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "InvalidIdentityToken", "web identity token is invalid", "Sender")
			return
		}

		expires := time.Now().UTC().Add(time.Hour)
		if claims.Expiry.Before(expires) {
			expires = claims.Expiry
		}

		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = xml.NewEncoder(w).Encode(assumeRoleResponse{
			XMLNS: stsNamespace,
			Result: assumeRoleResult{
				Subject:         claims.Subject,
				Audience:        *audience,
				Provider:        claims.Issuer,
				AssumedRoleUser: assumedRoleUser{ID: "mock:" + r.Form.Get("RoleSessionName"), ARN: r.Form.Get("RoleArn")},
				Credentials: credentials{
					AccessKeyID:     *accessKeyID,
					SecretAccessKey: *secretAccessKey,
					SessionToken:    uuid.NewV7().String(),
					Expiration:      expires.Format(time.RFC3339),
				},
			},
			Metadata: responseMetadata{RequestID: uuid.NewV7().String()},
		})
	}))
}

func main() {
	if err := run(); err != nil {
		slog.Error("failed to run server", "error", err)
		os.Exit(1)
	}
}

type assumeRoleResponse struct {
	XMLName  xml.Name         `xml:"AssumeRoleWithWebIdentityResponse"`
	XMLNS    string           `xml:"xmlns,attr"`
	Result   assumeRoleResult `xml:"AssumeRoleWithWebIdentityResult"`
	Metadata responseMetadata `xml:"ResponseMetadata"`
}
type assumeRoleResult struct {
	Credentials      credentials     `xml:"Credentials"`
	Subject          string          `xml:"SubjectFromWebIdentityToken"`
	AssumedRoleUser  assumedRoleUser `xml:"AssumedRoleUser"`
	PackedPolicySize int             `xml:"PackedPolicySize"`
	Audience         string          `xml:"Audience"`
	Provider         string          `xml:"Provider"`
}
type credentials struct {
	AccessKeyID     string `xml:"AccessKeyId"`
	SecretAccessKey string `xml:"SecretAccessKey"`
	SessionToken    string `xml:"SessionToken"`
	Expiration      string `xml:"Expiration"`
}
type assumedRoleUser struct {
	ID  string `xml:"AssumedRoleId"`
	ARN string `xml:"Arn"`
}
type responseMetadata struct {
	RequestID string `xml:"RequestId"`
}
type errorResponse struct {
	XMLName   xml.Name `xml:"ErrorResponse"`
	XMLNS     string   `xml:"xmlns,attr"`
	Error     apiError `xml:"Error"`
	RequestID string   `xml:"RequestId"`
}
type apiError struct {
	Type    string `xml:"Type"`
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}
