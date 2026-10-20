package auth

import (
	"strconv"
	"testing"
	"time"
)

func TestRestoredAPIDeniesEarlierSignedJWTAndAcceptsFreshLogin(t *testing.T) {
	for _, test := range []struct {
		name string
		iat  any
		want int
	}{
		{"old valid signed session", sessionTestNow.Add(-time.Second).Unix(), 401},
		{"at boundary", sessionTestNow.Unix(), 200},
		{"missing issuance", nil, 401},
	} {
		t.Run(test.name, func(t *testing.T) {
			a, sign := signedAuth(t, sessionTestNow)
			if err := SetTokenNotBefore(a, strconv.FormatInt(sessionTestNow.Unix(), 10)); err != nil {
				t.Fatal(err)
			}
			claims := syntheticClaims()
			if test.iat == nil {
				delete(claims, "iat")
			} else {
				claims["iat"] = test.iat
			}
			_, _, response := captureSession(t, a, sign(marshalClaims(t, claims)))
			if response.Code != test.want {
				t.Fatalf("status %d; expected %d", response.Code, test.want)
			}
		})
	}
}

func TestRestoreBoundaryCannotWeakenNormalSignatureAndExpiryVerification(t *testing.T) {
	a, sign := signedAuth(t, sessionTestNow)
	if err := SetTokenNotBefore(a, strconv.FormatInt(sessionTestNow.Add(-time.Hour).Unix(), 10)); err != nil {
		t.Fatal(err)
	}
	claims := syntheticClaims()
	claims["exp"] = sessionTestNow.Add(-time.Second).Unix()
	_, _, response := captureSession(t, a, sign(marshalClaims(t, claims)))
	if response.Code != 401 {
		t.Fatal("expired token admitted", response.Code)
	}
	_, wrongSigner := signedAuth(t, sessionTestNow)
	_, _, response = captureSession(t, a, wrongSigner(marshalClaims(t, syntheticClaims())))
	if response.Code != 401 {
		t.Fatal("foreign signature admitted", response.Code)
	}
}

func TestRestoreBoundaryConfigurationFailsClosed(t *testing.T) {
	for _, value := range []string{"0", "-1", "+1", "01", " 1", "1\n", "1.5", "2147483648", "bad"} {
		a, _ := signedAuth(t, sessionTestNow)
		if err := SetTokenNotBefore(a, value); err == nil {
			t.Fatalf("accepted invalid boundary %q", value)
		}
	}
	if err := SetTokenNotBefore(nil, "1"); err == nil {
		t.Fatal("accepted missing verifier")
	}
	a, sign := signedAuth(t, sessionTestNow)
	if err := SetTokenNotBefore(a, ""); err != nil {
		t.Fatal(err)
	}
	_, _, response := captureSession(t, a, sign(marshalClaims(t, syntheticClaims())))
	if response.Code != 200 {
		t.Fatal("normal appliance login changed", response.Code)
	}
}
