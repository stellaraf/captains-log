package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestStartupOutageProcess(t *testing.T) {
	if os.Getenv("NEBULALOG_OUTAGE_HELPER") != "1" {
		return
	}
	os.Args = []string{"nebulalog", os.Getenv("NEBULALOG_OUTAGE_ROLE")}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if err := run(); err != nil && !errors.Is(err, context.Canceled) {
		os.Exit(2)
	}
	os.Exit(0)
}

func TestCollectorStartsWithDatabasesAndIdentityOffline(t *testing.T) {
	for _, role := range []string{"ingest", "all"} {
		t.Run(role, func(t *testing.T) {
			spool := t.TempDir()
			child := exec.Command(os.Args[0], "-test.run=^TestStartupOutageProcess$")
			child.Env = append(os.Environ(), "NEBULALOG_OUTAGE_HELPER=1", "NEBULALOG_OUTAGE_ROLE="+role, "REQUIRE_FIPS=false",
				"PG_DSN=postgres://unit_test@127.0.0.1:1/offline?sslmode=disable&connect_timeout=1", "CH_URL=http://127.0.0.1:1",
				"OIDC_ISSUER=http://127.0.0.1:1/realms/offline", "OIDC_BACKCHANNEL_URL=", "SYSLOG_UDP=127.0.0.1:0", "SYSLOG_TCP=", "SYSLOG_TLS=", "SPOOL_DIR="+spool)
			stderr, err := child.StderrPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err = child.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- child.Wait() }()
			defer func() {
				_ = child.Process.Signal(syscall.SIGTERM)
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					_ = child.Process.Kill()
					<-done
				}
			}()
			addresses := make(chan string, 1)
			go func() {
				scanner := bufio.NewScanner(stderr)
				for scanner.Scan() {
					var entry struct {
						Message   string `json:"msg"`
						Listeners []struct {
							Address string `json:"address"`
						} `json:"listeners"`
					}
					if json.Unmarshal(scanner.Bytes(), &entry) == nil && entry.Message == "syslog collector listening" && len(entry.Listeners) > 0 {
						addresses <- entry.Listeners[0].Address
						return
					}
				}
			}()
			var address string
			select {
			case address = <-addresses:
			case err := <-done:
				done <- err
				t.Fatalf("collector stopped during dependency outage: %v", err)
			case <-time.After(8 * time.Second):
				t.Fatal("collector did not start while dependencies were offline")
			}
			socket, err := net.Dial("udp", address)
			if err != nil {
				t.Fatal(err)
			}
			_, err = socket.Write([]byte("<14>Sep 7 12:00:00 unit-test malformed PAN-OS record retained during startup outage"))
			socket.Close()
			if err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(3 * time.Second)
			persisted := false
			for time.Now().Before(deadline) {
				paths, _ := filepath.Glob(filepath.Join(spool, "*.wal"))
				for _, p := range paths {
					info, err := os.Stat(p)
					if err == nil && info.Size() > 0 {
						persisted = true
					}
				}
				if persisted {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !persisted {
				t.Fatal("event was not written to durable spool")
			}
			select {
			case err := <-done:
				done <- err
				t.Fatalf("collector exited after receiving while dependencies offline: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
		})
	}
}
