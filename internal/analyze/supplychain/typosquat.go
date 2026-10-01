package supplychain

// popularPackages is a seed list of well-known MCP-related package names used
// for typosquat detection. It is intentionally small and curated (not the full
// registry): a name a keystroke away from one of these, but not equal to it, is
// the classic squat. Extend this list as the ecosystem grows; the index service
// (Phase 3) will check against the full crawled registry.
var popularPackages = []string{
	"@modelcontextprotocol/server-filesystem",
	"@modelcontextprotocol/server-postgres",
	"@modelcontextprotocol/server-github",
	"@modelcontextprotocol/server-gitlab",
	"@modelcontextprotocol/server-slack",
	"@modelcontextprotocol/server-memory",
	"@modelcontextprotocol/server-puppeteer",
	"@modelcontextprotocol/server-brave-search",
	"@modelcontextprotocol/server-google-maps",
	"@modelcontextprotocol/server-sqlite",
	"@modelcontextprotocol/server-everything",
	"@modelcontextprotocol/sdk",
	"mcp-server-fetch",
	"mcp-server-git",
	"mcp-server-time",
}

// squat is a popular package that a scanned name imitates.
type squat struct {
	target   string // the popular package being imitated
	sameName bool   // same name under another scope, rather than a near spelling
	distance int    // edit distance between the unscoped names; 0 when sameName
}

// nearestSquat reports the popular package that name imitates, or ok=false.
// A popular package is never a squat of another, so exact matches are checked
// against the whole list first. Then the same unscoped name under a different
// scope (@evil/server-postgres) counts, since that is the cheapest squat to
// publish. Last, the closest name one or two edits away on the unscoped part.
func nearestSquat(name string) (squat, bool) {
	for _, p := range popularPackages {
		if p == name {
			return squat{}, false
		}
	}
	tail := unscoped(name)
	for _, p := range popularPackages {
		if unscoped(p) == tail {
			return squat{target: p, sameName: true}, true
		}
	}
	best := squat{distance: 3}
	for _, p := range popularPackages {
		if d := levenshtein(tail, unscoped(p)); d < best.distance {
			best = squat{target: p, distance: d}
		}
	}
	return best, best.target != ""
}

func unscoped(name string) string {
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '/' {
			return name[i+1:]
		}
	}
	return name
}

// levenshtein is the standard edit distance between two strings.
func levenshtein(a, b string) int {
	if a == b {
		return 0
	}
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min3(curr[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}
