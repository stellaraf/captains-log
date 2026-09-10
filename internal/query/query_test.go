package query

import (
	"strings"
	"testing"
)

func TestCompiler(t *testing.T) {
	for _, s := range []string{"( addr.src in 10.150.1.161 )", "( addr.src in 10.0.0.0/8 ) and (action eq allow) and (port.dst eq 443)", "NOT ((app eq ssl) OR (app eq web-browsing))", "addr.dst in 2001:db8::/32", "addr.src not-in ::1/128", "rule eq \"Default Outbound\"", "bytes >= 1024", "user.src contains \"ACME\\wayne\""} {
		if _, e := Compile(s); e != nil {
			t.Errorf("%s: %v", s, e)
		}
	}
}
func TestNoInterpolation(t *testing.T) {
	s := `rule eq "'; DROP TABLE events; --"`
	c, e := Compile(s)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(c.SQL, "DROP") || c.Params["q0"] != "'; DROP TABLE events; --" {
		t.Fatalf("not parameterized: %+v", c)
	}
}
func TestBooleanPrecedence(t *testing.T) {
	n, e := Parse("app eq ssl or action eq deny and not port.dst eq 443")
	if e != nil || n.Kind != "or" || n.Right.Kind != "and" || n.Right.Right.Kind != "not" {
		t.Fatalf("bad AST %+v %v", n, e)
	}
}
func TestReject(t *testing.T) {
	for _, s := range []string{"(app eq ssl))", "app eq", "app eq \"unterminated", "unknown eq x", "port.dst eq -1", "port.dst eq 65536", "port.dst contains 4", "addr.src in 10.1.1.1/99", "addr.src eq nope", "app eq ssl; DROP TABLE x", "addr.dst contains abc", strings.Repeat("not ", 40) + "app eq ssl", strings.Repeat("x", 8193)} {
		if _, e := Compile(s); e == nil {
			t.Errorf("accepted %q", s)
		}
	}
}
func TestIPv6Canonical(t *testing.T) {
	c, e := Compile("addr.dst eq 2001:0db8:0000::1")
	if e != nil || c.Params["q0"] != "2001:db8::1" {
		t.Fatal(c, e)
	}
	c, e = Compile("addr.src in 10.2.3.4/8")
	if e != nil || c.Params["q0"] != "10.0.0.0/8" {
		t.Fatal(c, e)
	}
}
func FuzzCompiler(f *testing.F) {
	f.Add("(app eq ssl)")
	f.Add("addr.src in ::/0")
	f.Fuzz(func(t *testing.T, s string) { _, _ = Compile(s) })
}
