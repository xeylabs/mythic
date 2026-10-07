// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

// Verify a Mythic decision token with the Go xtoken package against a live
// mythicd JWKS. Usage: go run . --base <url> --token <token>
// Prints {"dec","risk","sid"} as JSON.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/xeylabs/mythic/server/xtoken"
)

func main() {
	base := flag.String("base", "", "mythicd base URL")
	token := flag.String("token", "", "decision token")
	flag.Parse()
	if *base == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "usage: go run . --base <url> --token <token>")
		os.Exit(1)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(*base + "/v1/.well-known/jwks.json")
	if err != nil {
		fmt.Fprintln(os.Stderr, "jwks fetch:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	var jwks struct {
		Keys []struct {
			X string `json:"x"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		fmt.Fprintln(os.Stderr, "jwks decode:", err)
		os.Exit(1)
	}

	for _, k := range jwks.Keys {
		pub, err := xtoken.ParsePublicKey(k.X)
		if err != nil {
			continue
		}
		claims, err := xtoken.VerifyToken(pub, *token)
		if err != nil {
			continue
		}
		out, _ := json.Marshal(map[string]any{
			"dec":  string(claims.Decision),
			"risk": claims.Risk,
			"sid":  claims.SiteKey,
		})
		fmt.Println(string(out))
		return
	}
	fmt.Fprintln(os.Stderr, "no JWKS key verified the token")
	os.Exit(1)
}
