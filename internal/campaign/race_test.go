//go:build race

package campaign

// raceEnabled relaxes timing bounds under the race detector, whose
// instrumentation slows map-heavy code several-fold.
const raceEnabled = true
