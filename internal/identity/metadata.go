package identity

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"io"
	"net/url"
	"strings"
	"time"
)

const MaxMetadataBytes = 256 << 10
const metadataNS = "urn:oasis:names:tc:SAML:2.0:metadata"
const redirectBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
const postBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
const persistentNameID = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"

type endpoint struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}
type metadata struct {
	XMLName    xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntityID   string   `xml:"entityID,attr"`
	ValidUntil string   `xml:"validUntil,attr"`
	Providers  []struct {
		Protocols  string     `xml:"protocolSupportEnumeration,attr"`
		ValidUntil string     `xml:"validUntil,attr"`
		SSO        []endpoint `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleSignOnService"`
		SLO        []endpoint `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleLogoutService"`
		Keys       []struct {
			Use  string `xml:"use,attr"`
			Info struct {
				Data struct {
					Certs []string `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
				} `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
			} `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
		} `xml:"urn:oasis:names:tc:SAML:2.0:metadata KeyDescriptor"`
	} `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
}
type parsedMetadata struct {
	issuer, sso, slo, binding string
	keys                      []string
	certificates              []Certificate
}

func validateURL(raw string, allowHTTP bool) bool {
	if len(raw) == 0 || len(raw) > 2048 {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && u.Hostname() != "" && u.User == nil && u.Fragment == "" &&
		(u.Scheme == "https" || (allowHTTP && u.Scheme == "http"))
}
func inspectCertificate(raw string, now time.Time) (Certificate, string, error) {
	return parseCertificate(raw, now, true)
}
func parseCertificate(raw string, now time.Time, requireCurrent bool) (Certificate, string, error) {
	encoded := strings.Join(strings.Fields(raw), "")
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(der) > 16384 {
		return Certificate{}, "", problem("validation", "Invalid SAML signing certificate")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return Certificate{}, "", problem("validation", "Invalid SAML signing certificate")
	}
	valid := !now.Before(cert.NotBefore) && now.Before(cert.NotAfter)
	if requireCurrent && !valid {
		return Certificate{}, "", problem("validation", "SAML signing certificate is not currently valid")
	}
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 {
			return Certificate{}, "", problem("validation", "SAML RSA signing key must be at least 2048 bits")
		}
	case *ecdsa.PublicKey:
		if key.Curve.Params().BitSize < 256 {
			return Certificate{}, "", problem("validation", "SAML elliptic curve signing key is too small")
		}
	default:
		return Certificate{}, "", problem("validation", "Unsupported SAML signing key type")
	}
	sum := sha256.Sum256(der)
	return Certificate{CurrentlyValid: valid, SHA256: hex.EncodeToString(sum[:]), Subject: cert.Subject.String(), NotBefore: cert.NotBefore, NotAfter: cert.NotAfter}, base64.StdEncoding.EncodeToString(der), nil
}
func parseMetadata(raw string, allowHTTP bool, now time.Time) (parsedMetadata, error) {
	var out parsedMetadata
	bad := func(message string) (parsedMetadata, error) { return out, problem("validation", message) }
	if len(raw) == 0 || len(raw) > MaxMetadataBytes {
		return bad("Upload one IdP metadata XML document of at most 256 KiB")
	}
	// Tokenize before decoding structures: no directives, entities, include processing,
	// external references, multiple roots, or unbounded nesting. encoding/xml performs
	// no network/file resolution; every accepted byte comes from this upload.
	dec := xml.NewDecoder(strings.NewReader(raw))
	depth, roots, tokens := 0, 0, 0
	for {
		token, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return bad("Invalid metadata XML")
		}
		tokens++
		if tokens > 20000 {
			return bad("Metadata XML is too complex")
		}
		switch v := token.(type) {
		case xml.Directive:
			return bad("XML directives and entities are not permitted")
		case xml.ProcInst:
			if v.Target != "xml" {
				return bad("XML processing instructions are not permitted")
			}
		case xml.StartElement:
			if depth == 0 {
				roots++
			}
			depth++
			if depth > 32 || roots > 1 {
				return bad("Upload one bounded EntityDescriptor")
			}
			if v.Name.Space == "http://www.w3.org/2001/XInclude" || v.Name.Local == "AdditionalMetadataLocation" {
				return bad("External XML resources are not permitted")
			}
			if v.Name.Space == "http://www.w3.org/2000/09/xmldsig#" && (v.Name.Local == "Reference" || v.Name.Local == "RetrievalMethod") {
				for _, a := range v.Attr {
					if a.Name.Local == "URI" && a.Value != "" && !strings.HasPrefix(a.Value, "#") {
						return bad("External XML references are not permitted")
					}
				}
			}
		case xml.EndElement:
			depth--
		case xml.CharData:
			if depth == 0 && strings.TrimSpace(string(v)) != "" {
				return bad("Unexpected text outside metadata")
			}
		}
	}
	if roots != 1 || depth != 0 {
		return bad("Upload one complete EntityDescriptor")
	}
	var document metadata
	if err := xml.Unmarshal([]byte(raw), &document); err != nil || len(document.Providers) != 1 {
		return bad("Metadata must contain exactly one SAML IdP descriptor")
	}
	issuer, err := url.Parse(document.EntityID)
	if err != nil || issuer.Scheme == "" || len(document.EntityID) > 2048 || strings.ContainsAny(document.EntityID, "\r\n\t") {
		return bad("Metadata has an invalid identity provider entity ID")
	}
	if document.ValidUntil != "" {
		until, err := time.Parse(time.RFC3339Nano, document.ValidUntil)
		if err != nil || !now.Before(until) {
			return bad("Metadata has expired or has invalid validity")
		}
	}
	idp := document.Providers[0]
	if idp.ValidUntil != "" {
		until, err := time.Parse(time.RFC3339Nano, idp.ValidUntil)
		if err != nil || !now.Before(until) {
			return bad("Identity provider descriptor has expired or has invalid validity")
		}
	}
	if !strings.Contains(" "+idp.Protocols+" ", " urn:oasis:names:tc:SAML:2.0:protocol ") {
		return bad("Metadata does not advertise SAML 2.0")
	}
	choose := func(endpoints []endpoint) (endpoint, error) {
		var selected endpoint
		for _, e := range endpoints {
			if !validateURL(e.Location, allowHTTP) {
				return endpoint{}, problem("validation", "IdP endpoints must be absolute HTTPS URLs without credentials or fragments")
			}
			if e.Binding != redirectBinding && e.Binding != postBinding {
				continue
			}
			if selected.Binding == e.Binding && selected.Location != e.Location {
				return endpoint{}, problem("validation", "Metadata has ambiguous SAML endpoints")
			}
			if selected.Location == "" || e.Binding == redirectBinding {
				selected = e
			}
		}
		return selected, nil
	}
	sso, err := choose(idp.SSO)
	if err != nil {
		return out, err
	}
	if sso.Location == "" {
		return bad("Metadata is missing a supported SSO endpoint")
	}
	slo, err := choose(idp.SLO)
	if err != nil {
		return out, err
	}
	seen := map[string]bool{}
	for _, key := range idp.Keys {
		if key.Use != "" && key.Use != "signing" {
			continue
		}
		for _, rawCert := range key.Info.Data.Certs {
			cert, encoded, err := inspectCertificate(rawCert, now)
			if err != nil {
				return out, err
			}
			if !seen[cert.SHA256] {
				out.keys = append(out.keys, encoded)
				out.certificates = append(out.certificates, cert)
				seen[cert.SHA256] = true
			}
			if len(out.keys) > 8 {
				return bad("Metadata has too many signing certificates")
			}
		}
	}
	if len(out.keys) == 0 {
		return bad("Metadata is missing a valid signing certificate")
	}
	out.issuer, out.sso, out.slo, out.binding = document.EntityID, sso.Location, slo.Location, sso.Binding
	return out, nil
}
