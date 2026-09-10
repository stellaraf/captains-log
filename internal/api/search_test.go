package api

import (
	"strings"
	"testing"
	"time"
)

func TestSearchBounds(t *testing.T) {
	for _, s := range []Search{{LogType: "'; DROP TABLE events"}, {Sort: "id; DROP TABLE events"}, {Order: "desc LIMIT 99999"}, {From: "tomorrow"}, {From: time.Now().Format(time.RFC3339), To: time.Now().Add(-time.Hour).Format(time.RFC3339)}} {
		if _, _, e := buildSearch(&s); e == nil {
			t.Fatalf("unsafe search accepted %+v", s)
		}
	}
}
func TestSearchParameters(t *testing.T) {
	s := Search{LogType: "traffic", Query: `rule eq "quoted' rule"`}
	sql, params, e := buildSearch(&s)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(sql, "quoted") || params["q0"] != "quoted' rule" || params["category"] != "traffic" {
		t.Fatal(sql, params)
	}
	if s.From == "" || s.To == "" {
		t.Fatal("unbounded range")
	}
}
func TestCSVFormulaSafety(t *testing.T) {
	for _, s := range []string{"=CMD()", "+123", "-SUM(A1:A2)", "@SUM(A1:A2)", "\t=1", "\r=1"} {
		if !strings.HasPrefix(SafeCSV(s), "'") {
			t.Fatal(s)
		}
	}
	if SafeCSV("192.0.2.1") != "192.0.2.1" {
		t.Fatal("IP changed")
	}
}

func TestCSVLeadingNewlineCannotIntroduceFormula(t *testing.T) {
	if got := SafeCSV("\n=HYPERLINK(\"https://example.invalid\")"); got[0] != '\'' {
		t.Fatalf("unsafe CSV prefix: %q", got)
	}
}

func TestDuplicateEnrichmentColumnsRejected(t *testing.T) {
	if validColumns([]string{"src_hostname", "src_hostname"}) {
		t.Fatal("duplicate hostname columns accepted")
	}
	if !validColumns([]string{"src_ip", "src_hostname", "dst_ip", "dst_hostname"}) {
		t.Fatal("distinct enrichment columns rejected")
	}
}
