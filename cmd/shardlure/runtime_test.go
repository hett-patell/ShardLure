package main

import (
	"context"
	"flag"
	"github.com/networkshard/shardlure/internal/config"
	"github.com/networkshard/shardlure/internal/observability"
	"github.com/networkshard/shardlure/internal/settings"
	"github.com/networkshard/shardlure/internal/store"
	"gopkg.in/yaml.v3"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestRuntimeProductionAdapterServesAndJoins(t *testing.T) {
	for _, live := range []bool{false, true} {
		t.Run(map[bool]string{false: "web", true: "live"}[live], func(t *testing.T) {
			cfg := config.Default()
			cfg.DataDir = t.TempDir()
			cfg.Capture.Enabled = false
			cfg.RetentionDays = 0
			cfg.Observability.MinFreeBytes = 0
			cfg.Cowrie.JSONLog = filepath.Join(cfg.DataDir, "missing.json")
			cfg.GeoIP.Enabled = false
			st, err := store.Open(cfg.DBPath())
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			keys, err := settings.Load(st)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			bound := make(chan string, 1)
			done := make(chan error, 1)
			go func() {
				done <- runRuntime(ctx, st, keys, cfg, runtimeOptions{Addr: "127.0.0.1:0", Live: live, CowriePath: cfg.Cowrie.JSONLog, Interval: time.Second, OnListening: func(a net.Addr) { bound <- a.String() }})
			}()
			var addr string
			select {
			case addr = <-bound:
			case err := <-done:
				t.Fatalf("startup: %v", err)
			case <-time.After(3 * time.Second):
				t.Fatal("no listener")
			}
			client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: time.Second}
			defer client.CloseIdleConnections()
			deadline := time.Now().Add(3 * time.Second)
			ready := false
			for time.Now().Before(deadline) {
				resp, err := client.Get("http://" + addr + "/readyz")
				if err == nil {
					ready = resp.StatusCode == 200
					resp.Body.Close()
				}
				if ready {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !ready {
				t.Error("production adapter never ready")
			}
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("runtime did not join")
			}
			if _, err := st.EventCount(); err == nil {
				t.Fatal("runtime did not close owned store")
			}
		})
	}
}

func TestRuntimeWorkerFailureAndRecovery(t *testing.T) {
	m := observability.New(time.Now, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	calls := 0
	go func() {
		defer close(done)
		runPeriodicWorker(ctx, m, observability.CowrieIngest, time.Millisecond, time.Second, func(context.Context) error {
			calls++
			if calls == 1 {
				return context.DeadlineExceeded
			}
			return nil
		})
	}()
	deadline := time.After(time.Second)
	for m.Snapshot().Workers[observability.CowrieIngest].LastSuccess.IsZero() {
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatal("worker never recovered")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	<-done
	if calls < 2 || m.Snapshot().Workers[observability.CowrieIngest].LastSuccess.IsZero() {
		t.Fatal("worker did not recover after failed cycle")
	}
}

func TestRuntimeMainUsesProductionLifecycle(t *testing.T) {
	if os.Getenv("SHARDLURE_RUNTIME_MAIN") == "1" {
		os.Args = []string{"shardlure", "-config", os.Getenv("SHARDLURE_RUNTIME_CONFIG"), "live", os.Getenv("SHARDLURE_RUNTIME_ADDR"), "--no-journal"}
		flag.CommandLine = flag.NewFlagSet("shardlure", flag.ExitOnError)
		main()
		return
	}
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.Capture.Enabled = false
	cfg.GeoIP.Enabled = false
	cfg.RetentionDays = 0
	cfg.Observability.MinFreeBytes = 0
	cfg.Cowrie.JSONLog = filepath.Join(cfg.DataDir, "missing.json")
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.DataDir, "config.yaml")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()
	child := exec.Command(os.Args[0], "-test.run=^TestRuntimeMainUsesProductionLifecycle$")
	child.Env = append(os.Environ(), "SHARDLURE_RUNTIME_MAIN=1", "SHARDLURE_RUNTIME_CONFIG="+path, "SHARDLURE_RUNTIME_ADDR="+addr)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer child.Process.Kill()
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 200 * time.Millisecond}
	defer client.CloseIdleConnections()
	ready := false
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		res, err := client.Get("http://" + addr + "/readyz")
		if err == nil {
			ready = res.StatusCode == 200
			res.Body.Close()
		}
		if ready {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		child.Process.Kill()
		<-done
		t.Fatal("main never wired operational readiness")
	}
	if err := child.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SIGTERM did not join runtime")
	}
}
