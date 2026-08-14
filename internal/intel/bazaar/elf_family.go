package bazaar

import (
	"bytes"
	"debug/elf"
	"math"
)

// ELF malware-family fingerprinting for Linux/IoT botnet samples.
//
// The prior matcher did a literal case-insensitive substring search for family
// names ("mirai", "gafgyt", ...), which fails on stripped and UPX-packed
// samples where the name is not a cleartext string — measured at 0 family hits
// across 142 captured ELFs. This replaces it with precision-first fingerprints
// drawn from published YARA rules (Yara-Rules, Neo23x0/signature-base, Elastic
// protections-artifacts) and confirmed against the live capture corpus.
//
// GOVERNING RULE: Mirai, Gafgyt/Bashlite and Mozi share a code lineage, so a
// lone generic string (PING, /bin/busybox, an IRC verb, a raw 0xDEADBEEF) is
// LOW precision and MUST NEVER attribute a family alone. A family is emitted
// only on a Tier-A anchor. Precision >> recall: a WRONG family gets the shared
// abuse.ch account banned (bazaar + urlhaus + threatfox all die), so when in
// doubt we return "" and let the sample stay unattributed. See lowPrecisionMarkers.
//
// STRUCTURAL FACT: stripping removes the symbol table but not .rodata/.data
// string constants, so the resilient Mirai signature is the XOR-obfuscated
// credential wordlist in .rodata (decoded here), not the leaked-source function
// names (which only survive in un-stripped builds; used only as corroboration).

// matchELFFamily returns (family, tags) for an ELF buffer, or ("", nil) when no
// Tier-A anchor matched. family is the classifier's family slug (mapped to a
// Malpedia label downstream by threatfox); tags are descriptive tags added to
// the MalwareBazaar submission regardless of family confidence.
func matchELFFamily(buf []byte) (string, []string) {
	low := bytes.ToLower(buf)

	// --- Mozi (Mirai-derived P2P/DHT botnet) --------------------------------
	// Tier-A: the self-referential family name (near-unique), OR the fixed
	// 16-byte config XOR key together with the on-disk encrypted-config marker.
	// Deliberately NOT the BitTorrent DHT bootstrap hosts — those are real
	// public BT infrastructure present in every legit torrent client.
	if bytes.Contains(buf, []byte("Mozi.m")) || bytes.Contains(buf, []byte("Mozi.a")) ||
		containsWord(buf, []byte("Mozi")) {
		return "Mozi", []string{"botnet", "mozi", "mirai-lineage"}
	}
	if bytes.Contains(buf, moziXORKey) && bytes.Contains(buf, moziConfigMarker) {
		return "Mozi", []string{"botnet", "mozi", "mirai-lineage"}
	}

	// --- Mirai --------------------------------------------------------------
	// Tier-A anchors, in resilience order:
	//  (a) the NUL-embedded flood template (survives stripping, byte-pattern);
	//  (b) the .rodata XOR-obfuscated credential wordlist (survives stripping);
	//  (c) the /bin/busybox <TOKEN> + "<TOKEN>: applet not found" pair;
	//  (d) leaked-source symbols (un-stripped only) — corroboration.
	if bytes.Contains(buf, miraiCdnCgiTemplate) {
		return "Mirai", []string{"botnet", "mirai"}
	}
	if miraiXORWordlist(buf) {
		return "Mirai", []string{"botnet", "mirai"}
	}
	if bytes.Contains(low, []byte("applet not found")) && bytes.Contains(low, []byte("/bin/busybox")) {
		// The paired busybox-probe strings are Mirai-lineage; the applet-not-found
		// error only appears because the loader ran `/bin/busybox <TOKEN>`.
		return "Mirai", []string{"botnet", "mirai"}
	}
	if bytes.Contains(low, []byte("table_init")) && bytes.Contains(low, []byte("table_unlock_val")) {
		// Leaked-source table names — only in un-stripped builds, but unmistakable.
		return "Mirai", []string{"botnet", "mirai"}
	}

	// --- Gafgyt / Bashlite (a.k.a. IoT Qbot, Lizkebab, Torlus) --------------
	// Tier-A: the misspelled `gayfgt` busybox handshake (family-unique), the
	// scanner credential-exfil formats, or the HOLD+JUNK flood-verb pair (Mirai
	// uses numeric attack IDs, not these).
	if bytes.Contains(low, []byte("gayfgt")) || bytes.Contains(buf, gafgytOctalHandshake) {
		return "Gafgyt", []string{"botnet", "gafgyt", "bashlite"}
	}
	if bytes.Contains(buf, []byte("TELNET LOGIN CRACKED")) || bytes.Contains(buf, []byte("REPORT %s:%s:%s")) {
		return "Gafgyt", []string{"botnet", "gafgyt", "bashlite"}
	}
	if bytes.Contains(buf, []byte("HOLD")) && bytes.Contains(buf, []byte("JUNK")) &&
		bytes.Contains(low, []byte("/bin/busybox")) {
		return "Gafgyt", []string{"botnet", "gafgyt", "bashlite"}
	}

	// --- Tsunami / Kaiten (IRC-based) --------------------------------------
	// Tier-A: the Kaiten-unique command token GETSPOOFS plus a Tsunami/PAN
	// command and an IRC marker.
	if bytes.Contains(buf, []byte("GETSPOOFS")) &&
		(bytes.Contains(buf, []byte("TSUNAMI")) || bytes.Contains(buf, []byte("PAN "))) &&
		(bytes.Contains(buf, []byte("NOTICE %s :")) || bytes.Contains(buf, []byte("PRIVMSG"))) {
		return "Tsunami", []string{"botnet", "tsunami", "kaiten"}
	}

	// --- XMRig / cryptominer ------------------------------------------------
	// A miner is a TOOL, not a botnet family: attribute the tool tag, never a
	// family. Tier-A: the hardcoded dev-fee donate hosts (near-unique), or two
	// independent XMRig anchors.
	if bytes.Contains(low, []byte("donate.v2.xmrig.com")) || bytes.Contains(low, []byte("donate.ssl.xmrig.com")) {
		return "XMRig", []string{"miner", "xmrig", "coinminer"}
	}
	if xmrigAnchors(low) >= 2 {
		return "XMRig", []string{"miner", "xmrig", "coinminer"}
	}

	// --- named-in-the-clear families ---------------------------------------
	// These families brand themselves in .rodata (loader banners, pool config,
	// Docker pulls) and were reliably matched by the prior literal scan — keep
	// them. They are miner/proxyware droppers whose ELF/script variants carry
	// the literal name, which is itself a strong signal for these particular
	// families (unlike the generic-string trap the botnet families fall into).
	// mirai/gafgyt/tsunami literals are deliberately NOT here — those are
	// handled above by precision anchors so a stripped/packed variant that only
	// mentions the word in a comment cannot smuggle a botnet attribution.
	switch {
	case bytes.Contains(low, []byte("redtail")):
		return "RedTail", []string{"miner", "redtail"}
	case bytes.Contains(low, []byte("c3pool")):
		return "Coinminer", []string{"miner", "c3pool"}
	case bytes.Contains(low, []byte("traffmonetizer")):
		return "Traffmonetizer", []string{"proxyware", "traffmonetizer"}
	case bytes.Contains(low, []byte("komari")):
		return "Komari", []string{"botnet", "komari"}
	}

	return "", nil
}

// --- signature constants ---------------------------------------------------

// moziXORKey is Mozi's fixed 16-byte config encryption key; moziConfigMarker is
// the on-disk `[ss]` tag XORed by the first 4 key bytes. Together they are an
// effectively-zero-FP Mozi signature (360 Netlab teardown).
var moziXORKey = []byte{0x4E, 0x66, 0x5A, 0x8F, 0x80, 0xC8, 0xAC, 0x23, 0x8D, 0xAC, 0x47, 0x06, 0xD5, 0x4F, 0x6F, 0x7E}
var moziConfigMarker = []byte{0x15, 0x15, 0x29, 0xD2}

// miraiCdnCgiTemplate is Mirai's HTTP-flood format template assembled in
// .rodata with embedded NULs (so it is a byte-pattern, not a plain string):
//
//	"POST /cdn-cgi/\0\0 HTTP/1.1\r\nUser-Agent: \0\r\nHost:"
//
// (signature-base crime_mirai.yar rule MAL_ELF_LNX_Mirai_Oct10_2). The NULs are
// exactly why the old substring search never found it.
var miraiCdnCgiTemplate = []byte("POST /cdn-cgi/\x00\x00 HTTP/1.1\r\nUser-Agent: \x00\r\nHost:")

// gafgytOctalHandshake is the octal-escaped `gayfgt` some builds emit instead
// of the literal (`echo -e '\147\141\171\146\147\164'`).
var gafgytOctalHandshake = []byte(`\147\141\171\146\147\164`)

// miraiWordlistTargets are cleartext substrings that appear in Mirai's telnet
// credential wordlist / config once the .rodata run is XOR-decoded. Requiring
// TWO of them (below) keeps a lone common word from a coincidental decode from
// attributing Mirai.
var miraiWordlistTargets = [][]byte{
	[]byte("nameserver"), []byte("administrator"), []byte("listening"),
	[]byte("/bin/busybox"), []byte("assword"), []byte("supervisor"),
}

// miraiXORWordlist scans the buffer for Mirai's obfuscated .rodata wordlist by
// XORing the whole buffer with each of Mirai's single-byte collapsed keys
// (0x22 from 0xDEADBEEF, 0x54 from 0xDEDEFBAF) and testing for >=2 distinct
// wordlist targets in the decoded output. Two-hit minimum is the precision
// guard: a single decoded common word is not enough to attribute.
func miraiXORWordlist(buf []byte) bool {
	for _, key := range []byte{0x22, 0x54} {
		dec := make([]byte, len(buf))
		for i, b := range buf {
			dec[i] = b ^ key
		}
		hits := 0
		for _, t := range miraiWordlistTargets {
			if bytes.Contains(dec, t) {
				hits++
				if hits >= 2 {
					return true
				}
			}
		}
	}
	return false
}

// xmrigAnchors counts independent XMRig cleartext anchors (the UA format and
// the algorithm-name set). Used as a >=2 corroboration when the donate host is
// absent.
func xmrigAnchors(low []byte) int {
	n := 0
	if bytes.Contains(low, []byte("xmrig/")) && bytes.Contains(low, []byte("libuv/")) {
		n++
	}
	if bytes.Contains(low, []byte("rx/0")) && bytes.Contains(low, []byte("cn/r")) {
		n++
	}
	if bytes.Contains(low, []byte("randomx")) {
		n++
	}
	return n
}

// containsWord reports whether `word` appears in buf delimited by
// non-identifier bytes on both sides (so "Mozi" matches but "Mozilla" does
// not — the latter is the benign browser UA that would false-positive).
func containsWord(buf, word []byte) bool {
	from := 0
	for {
		i := bytes.Index(buf[from:], word)
		if i < 0 {
			return false
		}
		i += from
		beforeOK := i == 0 || !isIdentByte(buf[i-1])
		after := i + len(word)
		afterOK := after >= len(buf) || !isIdentByte(buf[after])
		if beforeOK && afterOK {
			return true
		}
		from = i + 1
	}
}

func isIdentByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

// lowPrecisionMarkers documents, in code, the shared/generic signatures that
// MUST NEVER attribute a family on their own. They are lineage-shared or
// benign-common, so keying attribution on them would false-positive and risk
// the shared abuse.ch account. This list exists so a future edit that tries to
// promote one of these to an anchor is caught by TestLowPrecisionMarkersNeverAttribute.
var lowPrecisionMarkers = [][]byte{
	[]byte("/bin/busybox"),           // every BusyBox device
	[]byte("PING"),                   // generic / lineage-shared
	[]byte("PONG"),                   // ditto (only "PONG!" with the bang is Gafgyt-leaning)
	[]byte("TSource Engine Query"),   // in Mirai, Tsunami, Gafgyt AND legit Source games
	[]byte("Mozilla/5.0"),            // benign browser UA in millions of binaries
	[]byte("8.8.8.8"),                // Google DNS
	[]byte("stratum+tcp"),            // every stratum miner, not XMRig-specific
	[]byte("argon2"),                 // password-hashing lib
	[]byte("Remote IRC Bot"),         // shared Gafgyt/Tsunami
	[]byte("dht.transmissionbt.com"), // real BitTorrent DHT bootstrap (benign)
	[]byte("router.bittorrent.com"),  // ditto
	{0xEF, 0xBE, 0xAD, 0xDE},         // raw 0xDEADBEEF little-endian — ubiquitous sentinel
}

// --- packing detection -----------------------------------------------------

// isPackedELF reports whether the buffer looks UPX-packed or otherwise packed,
// returning descriptive tags. It NEVER attributes a family — packing is a
// verdict signal (packed IoT dropper over SSH = suspicious) and a reason to
// WITHHOLD family attribution when no cleartext anchor survives. ef may be nil
// (structural checks are then skipped).
func isPackedELF(buf []byte, ef *elf.File) (bool, []string) {
	// UPX magic in header or tail, or the stub banner.
	upxMagic := []byte("UPX!")
	head := buf
	if len(head) > 1024 {
		head = head[:1024]
	}
	tail := buf
	if len(buf) > 1024 {
		tail = buf[len(buf)-1024:]
	}
	if bytes.Contains(head, upxMagic) || bytes.Contains(tail, upxMagic) ||
		bytes.Contains(buf, []byte("$Info: This file is packed with the UPX")) {
		return true, []string{"packed", "upx"}
	}
	// Tamper-markers IoT malware uses to break `upx -d` while keeping the stub
	// self-decompressing: YTS<x> (SBIDIOT/CUJO) and F5 96 A4 B5 (Hajime).
	if bytes.Contains(buf, []byte("YTS")) && looksLikeTamperedUPX(ef) {
		return true, []string{"packed", "upx"}
	}
	if bytes.Contains(head, []byte{0xF5, 0x96, 0xA4, 0xB5}) {
		return true, []string{"packed", "upx"}
	}
	// Structural fallback: a Writable+Executable PT_LOAD (packers need to write
	// the decompressed image into an executable segment) combined with very high
	// overall entropy is the packer shape even when magic is scrubbed.
	if ef != nil && hasWritableExecSegment(ef) && bufferEntropy(buf) > 7.2 {
		return true, []string{"packed"}
	}
	return false, nil
}

func looksLikeTamperedUPX(ef *elf.File) bool {
	// A tampered UPX ELF still has the packer's two-PT_LOAD shape.
	if ef == nil {
		return false
	}
	loads := 0
	for _, p := range ef.Progs {
		if p.Type == elf.PT_LOAD {
			loads++
		}
	}
	return loads > 0 && loads <= 2
}

func hasWritableExecSegment(ef *elf.File) bool {
	for _, p := range ef.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&elf.PF_W != 0 && p.Flags&elf.PF_X != 0 {
			return true
		}
	}
	return false
}

// bufferEntropy is the Shannon entropy (bits/byte) of the buffer. Packed or
// encrypted data trends toward 8.0; normal code/text sits well below.
func bufferEntropy(buf []byte) float64 {
	if len(buf) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range buf {
		counts[b]++
	}
	n := float64(len(buf))
	e := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}
