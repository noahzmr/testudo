package wireguard

// SubScore computes the WireGuard contribution to the Network Quality grade from
// a snapshot. It is a pure function so both the TUI and Web grade code can call
// it identically.
//
// Contract (matches the neutral-100 rule in M4):
//   - No WireGuard device at all -> score 100, hasData=false. A host without
//     WireGuard is never penalised; callers exclude a hasData=false sub-score
//     from the weighted grade entirely.
//   - Devices present but no peers -> score 100, hasData=true (healthy, nothing
//     to complain about).
//   - Otherwise the score is the fraction of peers whose handshake is healthy,
//     with graduated penalties for degraded/down/never-established peers.
func (s Snapshot) SubScore() (score int, hasData bool) {
	total := 0
	var penalty float64
	for _, d := range s.Devices {
		for _, p := range d.Peers {
			total++
			switch p.Severity {
			case SevWarn:
				penalty += 0.4
			case SevError:
				penalty += 0.8
			case SevCritical:
				penalty += 1.0
			}
		}
	}
	if len(s.Devices) == 0 {
		return 100, false // no WG device: neutral, excluded from the grade
	}
	if total == 0 {
		return 100, true // device up, no peers: healthy
	}
	frac := penalty / float64(total) // 0 (all healthy) .. 1 (all dead)
	score = max(int(100*(1-frac)+0.5), 0)
	return score, true
}

// Summary is the compact, secrets-free rollup the grade and UIs consume without
// walking the whole snapshot.
type Summary struct {
	Devices       int
	Peers         int
	HealthyPeers  int
	WorstSeverity Severity
}

// Summarize reduces a snapshot to counts + worst severity.
func (s Snapshot) Summarize() Summary {
	sum := Summary{Devices: len(s.Devices), WorstSeverity: SevOK}
	for _, d := range s.Devices {
		for _, p := range d.Peers {
			sum.Peers++
			if p.Severity == SevOK {
				sum.HealthyPeers++
			}
			if severityRank(p.Severity) > severityRank(sum.WorstSeverity) {
				sum.WorstSeverity = p.Severity
			}
		}
	}
	return sum
}
