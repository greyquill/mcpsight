// Package tokenize estimates how many tokens a piece of text costs a model.
//
// Phase 1 ships a heuristic Estimator behind the Tokenizer interface: it is
// deliberately labeled an estimate everywhere it surfaces, never a fake-precise
// number. The interface exists so a real BPE tokenizer (cl100k/o200k, or an
// open tokenizer for local models) can drop in without touching analyzers.
// We report per model FAMILY, not one universal number.
package tokenize

import "unicode"

// Tokenizer counts tokens for a given model family.
type Tokenizer interface {
	Count(text string) int
	Family() string
}

// Model describes a target for cost estimation: a family (which determines the
// tokenizer) and a published input price used to estimate per-request cost.
type Model struct {
	Name            string
	Family          string
	InputUSDPerMTok float64 // published input price per 1M tokens
	familyFactor    float64 // estimator adjustment relative to the base heuristic
}

// Models is the default set reported by the context-cost analyzer. Prices are
// published list prices and live here (not hard-coded in the analyzer) so they
// are easy to update. Token counts are ESTIMATES pending real BPE tokenizers.
var Models = []Model{
	{Name: "Claude Sonnet", Family: "anthropic", InputUSDPerMTok: 3.00, familyFactor: 1.00},
	{Name: "GPT (o200k)", Family: "openai", InputUSDPerMTok: 2.50, familyFactor: 0.95},
	{Name: "Llama (open)", Family: "open", InputUSDPerMTok: 0.20, familyFactor: 1.05},
}

// Estimator is a heuristic Tokenizer that approximates modern BPE behavior on
// the mixed English+JSON text of tool definitions. It is not exact; it is
// stable and offline. factor scales the base estimate to reflect that different
// families' tokenizers segment the same text slightly differently.
type Estimator struct {
	family string
	factor float64
}

// EstimatorFor returns a heuristic tokenizer for a model.
func EstimatorFor(m Model) Estimator {
	f := m.familyFactor
	if f == 0 {
		f = 1
	}
	return Estimator{family: m.Family, factor: f}
}

func (e Estimator) Family() string { return e.family }

// Count approximates BPE segmentation: runs of letters are split into ~4-rune
// sub-word chunks (as BPE does for longer words), digit runs into ~3-digit
// chunks (numbers), and each punctuation/symbol is its own token. Whitespace is
// free (merged into the following token, as leading-space tokenization does).
func (e Estimator) Count(text string) int {
	base := 0.0
	runLetters, runDigits := 0, 0
	flushL := func() {
		if runLetters > 0 {
			base += float64((runLetters + 3) / 4) // ~4 runes per sub-word token
			runLetters = 0
		}
	}
	flushD := func() {
		if runDigits > 0 {
			base += float64((runDigits + 2) / 3) // ~3 digits per number token
			runDigits = 0
		}
	}
	for _, r := range text {
		switch {
		case unicode.IsLetter(r):
			flushD()
			runLetters++
		case unicode.IsDigit(r):
			flushL()
			runDigits++
		case unicode.IsSpace(r):
			flushL()
			flushD()
		default:
			flushL()
			flushD()
			base++ // punctuation/symbol: one token each
		}
	}
	flushL()
	flushD()
	est := base * e.factor
	if est < 1 && len(text) > 0 {
		est = 1
	}
	return int(est + 0.5)
}
