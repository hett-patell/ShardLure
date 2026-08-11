.PHONY: build test fuzz run-sample deploy plant-bait

build:
	go mod tidy
	go build -o shardlure ./cmd/shardlure

test:
	go test ./...

# Opt-in fuzzing of the three parsers that consume attacker-controlled input:
# the sshd journal line parser, the cowrie jsonlog reader, and the cowrie TTY
# binary decoder. NOT part of `make test` or CI — CI already executes each
# target's seed corpus during `go test` (which is what catches regressions on
# known-bad inputs); this target is for exploring new ones.
#
# Override the budget per target with: make fuzz FUZZTIME=5m
FUZZTIME ?= 60s
fuzz:
	go test ./internal/ingest/journal/ -run=XXX -fuzz=FuzzParseLine     -fuzztime=$(FUZZTIME)
	go test ./internal/ingest/cowrie/  -run=XXX -fuzz=FuzzParseReader    -fuzztime=$(FUZZTIME)
	go test ./internal/capture/        -run=XXX -fuzz=FuzzDecodeTTYReader -fuzztime=$(FUZZTIME)

deploy:
	bash scripts/push-sources.sh arm

plant-bait:
	sudo python3 scripts/shardlure.py plant-bait

run-sample: build
	./shardlure ingest journal testdata/sample.journal --replace
	./shardlure actors
	./shardlure actor show 188.84.0.25
