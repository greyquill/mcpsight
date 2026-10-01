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

// nearestSquat returns a popular package name that `name` is suspiciously close
// to (edit distance 1–2 on the unscoped portion) without being identical, or ""
// if none. Comparing the unscoped tail catches squats that keep the scope.
func nearestSquat(name string) string {
	target := unscoped(name)
	for _, p := range popularPackages {
		if p == name {
			return "" // it *is* the popular package
		}
		d := levenshtein(target, unscoped(p))
		if d >= 1 && d <= 2 {
			return p
		}
	}
	return ""
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
