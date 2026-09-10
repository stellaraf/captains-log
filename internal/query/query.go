// Package query compiles a bounded PAN-OS-style expression to typed ClickHouse parameters.
package query

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
)

type Field struct {
	Alias     string   `json:"alias"`
	Column    string   `json:"column"`
	Label     string   `json:"label"`
	Type      string   `json:"type"`
	Operators []string `json:"operators"`
}

var Fields = []Field{
	{"addr.src", "src_ip", "Source Address", "ip", nil}, {"addr.dst", "dst_ip", "Destination Address", "ip", nil},
	{"port.src", "src_port", "Source Port", "port", nil}, {"port.dst", "dst_port", "Destination Port", "port", nil},
	{"zone.src", "src_zone", "From Zone", "string", nil}, {"zone.dst", "dst_zone", "To Zone", "string", nil},
	{"user.src", "src_user", "Source User", "string", nil}, {"user.dst", "dst_user", "Destination User", "string", nil},
	{"app", "app", "Application", "string", nil}, {"action", "action", "Action", "string", nil}, {"rule", "rule", "Rule", "string", nil},
	{"device", "serial", "Firewall Serial", "string", nil}, {"device.name", "device_name", "Device Name", "string", nil},
	{"vsys", "vsys", "VSYS", "string", nil}, {"type", "log_type", "Log Type", "string", nil}, {"subtype", "subtype", "Subtype", "string", nil},
	{"severity", "severity", "Severity", "string", nil}, {"bytes", "bytes", "Bytes", "uint", nil}, {"packets", "packets", "Packets", "uint", nil},
	{"session.id", "session_id", "Session ID", "string", nil}, {"nat.src", "nat_src_ip", "NAT Source", "ip", nil}, {"nat.dst", "nat_dst_ip", "NAT Destination", "ip", nil},
	{"parse.status", "parse_status", "Parse Status", "string", nil},
}

func init() {
	for i := range Fields {
		switch Fields[i].Type {
		case "ip":
			Fields[i].Operators = []string{"eq", "neq", "in", "not-in"}
		case "uint", "port":
			Fields[i].Operators = []string{"eq", "neq", "gt", "geq", "lt", "leq"}
		default:
			Fields[i].Operators = []string{"eq", "neq", "contains"}
		}
	}
}
func Lookup(alias string) (Field, bool) {
	for _, f := range Fields {
		if f.Alias == alias {
			return f, true
		}
	}
	return Field{}, false
}

type Token struct {
	Value  string
	Pos    int
	Quoted bool
}
type SyntaxError struct {
	Message  string
	Position int
}

func (e *SyntaxError) Error() string {
	return fmt.Sprintf("%s at character %d.", e.Message, e.Position)
}
func fail(msg string, pos int) error { return &SyntaxError{msg, pos} }
func Lex(input string) ([]Token, error) {
	r := []rune(input)
	if len(r) > 8192 {
		return nil, fail("Query exceeds 8192 characters", 8193)
	}
	ts := make([]Token, 0)
	for i := 0; i < len(r); {
		if unicode.IsSpace(r[i]) {
			i++
			continue
		}
		start := i
		if r[i] == '(' || r[i] == ')' {
			ts = append(ts, Token{string(r[i]), i + 1, false})
			i++
		} else if r[i] == '"' || r[i] == '\'' {
			quote := r[i]
			i++
			var v strings.Builder
			closed := false
			for i < len(r) {
				if r[i] == quote {
					i++
					closed = true
					break
				}
				if r[i] == '\\' && i+1 < len(r) && (r[i+1] == quote || r[i+1] == '\\') {
					i++
				}
				v.WriteRune(r[i])
				i++
			}
			if !closed {
				return nil, fail("Unterminated quoted value", start+1)
			}
			ts = append(ts, Token{v.String(), start + 1, true})
		} else {
			for i < len(r) && !unicode.IsSpace(r[i]) && r[i] != '(' && r[i] != ')' {
				if r[i] == '"' || r[i] == '\'' {
					return nil, fail("Quote must begin a value", i+1)
				}
				i++
			}
			ts = append(ts, Token{string(r[start:i]), start + 1, false})
		}
		if len(ts) > 1024 {
			return nil, fail("Query exceeds 1024 tokens", start+1)
		}
	}
	ts = append(ts, Token{"", len(r) + 1, false})
	return ts, nil
}

type Node struct {
	Kind            string
	Left, Right     *Node
	Field           Field
	Operator, Value string
	Position        int
}
type parser struct {
	t []Token
	i int
}

func (p *parser) peek() Token { return p.t[p.i] }
func (p *parser) match(s string) bool {
	t := p.peek()
	if !t.Quoted && strings.EqualFold(t.Value, s) {
		p.i++
		return true
	}
	return false
}
func Parse(s string) (*Node, error) {
	ts, e := Lex(s)
	if e != nil {
		return nil, e
	}
	p := parser{t: ts}
	if len(ts) == 1 {
		return nil, nil
	}
	n, e := p.or(0)
	if e != nil {
		return nil, e
	}
	if p.peek().Value != "" {
		return nil, fail("Unexpected '"+p.peek().Value+"'", p.peek().Pos)
	}
	return n, nil
}
func (p *parser) or(depth int) (*Node, error) {
	n, e := p.and(depth)
	if e != nil {
		return nil, e
	}
	for p.match("or") {
		r, e := p.and(depth)
		if e != nil {
			return nil, e
		}
		n = &Node{Kind: "or", Left: n, Right: r}
	}
	return n, nil
}
func (p *parser) and(depth int) (*Node, error) {
	n, e := p.unary(depth)
	if e != nil {
		return nil, e
	}
	for p.match("and") {
		r, e := p.unary(depth)
		if e != nil {
			return nil, e
		}
		n = &Node{Kind: "and", Left: n, Right: r}
	}
	return n, nil
}
func (p *parser) unary(depth int) (*Node, error) {
	if depth > 32 {
		return nil, fail("Maximum nesting depth is 32", p.peek().Pos)
	}
	if p.match("not") || p.match("!") {
		n, e := p.unary(depth + 1)
		return &Node{Kind: "not", Left: n}, e
	}
	if p.match("(") {
		n, e := p.or(depth + 1)
		if e != nil {
			return nil, e
		}
		if !p.match(")") {
			return nil, fail("Expected ')'", p.peek().Pos)
		}
		return n, nil
	}
	return p.predicate()
}
func (p *parser) predicate() (*Node, error) {
	t := p.peek()
	f, ok := Lookup(strings.ToLower(t.Value))
	if !ok || t.Quoted {
		return nil, fail("Expected a known filter attribute; got '"+t.Value+"'", t.Pos)
	}
	p.i++
	op := p.peek()
	if op.Value == "" {
		return nil, fail("Expected an operator", op.Pos)
	}
	p.i++
	o := strings.ToLower(op.Value)
	aliases := map[string]string{"=": "eq", "==": "eq", "!=": "neq", ">": "gt", ">=": "geq", "<": "lt", "<=": "leq", "gte": "geq", "lte": "leq"}
	if a, ok := aliases[o]; ok {
		o = a
	}
	valid := false
	for _, a := range f.Operators {
		if a == o {
			valid = true
		}
	}
	if !valid || op.Quoted {
		return nil, fail("Operator '"+o+"' is not valid for "+f.Alias, op.Pos)
	}
	v := p.peek()
	if !v.Quoted && (v.Value == "" || v.Value == "(" || v.Value == ")" || strings.EqualFold(v.Value, "and") || strings.EqualFold(v.Value, "or")) {
		return nil, fail("Expected a value", v.Pos)
	}
	p.i++
	if len(v.Value) > 2048 {
		return nil, fail("Value exceeds 2048 characters", v.Pos)
	}
	switch f.Type {
	case "ip":
		if o == "in" || o == "not-in" {
			if a, e := netip.ParseAddr(v.Value); e == nil && a.Zone() == "" {
				v.Value = netip.PrefixFrom(a, a.BitLen()).String()
			} else if a, e := netip.ParsePrefix(v.Value); e == nil {
				v.Value = a.Masked().String()
			} else {
				return nil, fail("Expected an IPv4/IPv6 address or CIDR", v.Pos)
			}
		} else {
			a, e := netip.ParseAddr(v.Value)
			if e != nil || a.Zone() != "" {
				return nil, fail("Expected an IPv4/IPv6 address", v.Pos)
			}
			v.Value = a.String()
		}
	case "uint", "port":
		n, e := strconv.ParseUint(v.Value, 10, 64)
		if e != nil || (f.Type == "port" && n > 65535) {
			return nil, fail("Expected a valid unsigned "+f.Type+" value", v.Pos)
		}
		v.Value = strconv.FormatUint(n, 10)
	}
	return &Node{Kind: "predicate", Field: f, Operator: o, Value: v.Value, Position: t.Pos}, nil
}

type Compiled struct {
	SQL    string
	Params map[string]string
	AST    *Node
}

func Compile(s string) (Compiled, error) {
	n, e := Parse(s)
	if e != nil {
		return Compiled{}, e
	}
	c := Compiled{Params: map[string]string{}, AST: n}
	var emit func(*Node) string
	emit = func(n *Node) string {
		if n == nil {
			return "1"
		}
		switch n.Kind {
		case "and", "or":
			return "(" + emit(n.Left) + " " + strings.ToUpper(n.Kind) + " " + emit(n.Right) + ")"
		case "not":
			return "(NOT " + emit(n.Left) + ")"
		}
		name := fmt.Sprintf("q%d", len(c.Params))
		c.Params[name] = n.Value
		typ := "String"
		if n.Field.Type == "port" {
			typ = "UInt16"
		}
		if n.Field.Type == "uint" {
			typ = "UInt64"
		}
		param := "{" + name + ":" + typ + "}"
		col := n.Field.Column
		if n.Operator == "in" || n.Operator == "not-in" {
			expr := "isIPAddressInRange(nullIf(" + col + ", ''), " + param + ")"
			if n.Operator == "not-in" {
				expr = "NOT " + expr
			}
			return "(" + expr + ")"
		}
		if n.Operator == "contains" {
			return "(positionCaseInsensitiveUTF8(" + col + ", " + param + ") > 0)"
		}
		op := map[string]string{"eq": "=", "neq": "!=", "gt": ">", "geq": ">=", "lt": "<", "leq": "<="}[n.Operator]
		return "(" + col + " " + op + " " + param + ")"
	}
	c.SQL = emit(n)
	return c, nil
}
