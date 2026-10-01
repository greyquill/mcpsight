package render

import (
	"encoding/json"
	"io"

	"github.com/greyquill/mcpsight/internal/scan"
)

// JSON writes the report as indented JSON — the machine-readable artifact and
// the format written to .mcpsight/report.json.
func JSON(w io.Writer, r *scan.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}
