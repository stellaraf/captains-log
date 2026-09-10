package api

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/stellaraf/captains-log/internal/panos"
	"github.com/stellaraf/captains-log/internal/store"
)

// This opt-in test runs real ClickHouse predicates over inline records. It
// inserts nothing and needs no production log data. HTTP mocks cannot verify
// the SQL's Boolean grouping or category membership.
func TestThreatMembershipClickHouse(t *testing.T) {
	endpoint := os.Getenv("NEBULALOG_TEST_CH_URL")
	if endpoint == "" {
		t.Skip("set NEBULALOG_TEST_CH_URL for read-only ClickHouse integration")
	}
	fixture, err := os.ReadFile("../panos/testdata/pa1410-12.1-dns.log")
	if err != nil {
		t.Fatal(err)
	}
	event := panos.Parse(fixture, "192.0.2.1", time.Now())
	if event.LogType != "dns" || event.WireType != "THREAT" || event.Subtype != "spyware" {
		t.Fatalf("real sanitized DNS fixture changed classification: %s/%s/%s", event.LogType, event.WireType, event.Subtype)
	}
	client := store.NewClickHouse(endpoint, os.Getenv("NEBULALOG_TEST_CH_USER"), os.Getenv("NEBULALOG_TEST_CH_PASSWORD"))
	const records = `values('id String, log_type String, wire_type String, action String, received_at DateTime64(6)',
	('ordinary','threat','THREAT','alert','2026-09-07 12:00:00'),
	('dns-detection','dns','THREAT','deny','2026-09-07 12:00:00'),
	('native-dns','dns','DNS','allow','2026-09-07 12:00:00'),
	('url-record','url','THREAT','alert','2026-09-07 12:00:00'),
	('wildfire-record','wildfire','THREAT','alert','2026-09-07 12:00:00'),
	('data-record','data','THREAT','alert','2026-09-07 12:00:00'),
	('traffic-record','traffic','TRAFFIC','deny','2026-09-07 12:00:00'),
	('old-dns','dns','THREAT','deny','2026-09-06 12:00:00'))`
	for _, test := range []struct {
		name, category, query string
		want                  []string
	}{
		{"threat includes DNS detections", "threat", "", []string{"dns-detection", "ordinary"}},
		{"DNS remains overlapping", "dns", "", []string{"dns-detection", "native-dns"}},
		{"manual filter still applies to both categories", "threat", "action eq deny", []string{"dns-detection"}},
		{"stored category filter remains explicit", "threat", "type eq threat", []string{"ordinary"}},
		{"URL remains separate", "url", "", []string{"url-record"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			search := Search{LogType: test.category, Query: test.query, From: "2026-09-07T11:00:00Z", To: "2026-09-07T13:00:00Z"}
			where, params, err := buildSearch(&search)
			if err != nil {
				t.Fatal(err)
			}
			rows, err := client.Rows(context.Background(), "SELECT id FROM "+records+" WHERE "+where+" ORDER BY id", params)
			if err != nil {
				t.Fatal(err)
			}
			got := []string{}
			for _, row := range rows {
				got = append(got, fmt.Sprint(row["id"]))
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("got %v, want %v", got, test.want)
			}
		})
	}
}
