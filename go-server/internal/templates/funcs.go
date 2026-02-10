package templates

import (
	"fmt"
	"html/template"
	"strings"
	"time"
)

func FuncMap() template.FuncMap {
	return template.FuncMap{
		"countryFlag": func(code string) string {
			if len(code) != 2 {
				return ""
			}
			code = strings.ToUpper(code)
			r1 := rune(0x1F1E6 + int(code[0]) - int('A'))
			r2 := rune(0x1F1E6 + int(code[1]) - int('A'))
			return string([]rune{r1, r2})
		},
		"formatDate": func(t time.Time) string {
			return t.Format("Jan 02, 2006 15:04 UTC")
		},
		"formatDuration": func(d float64) string {
			if d < 1.0 {
				return fmt.Sprintf("%.0fms", d*1000)
			}
			return fmt.Sprintf("%.1fs", d)
		},
		"upper": strings.ToUpper,
		"lower": strings.ToLower,
		"safeHTML": func(s string) template.HTML {
			return template.HTML(s)
		},
		"add": func(a, b int) int {
			return a + b
		},
		"sub": func(a, b int) int {
			return a - b
		},
		"mul": func(a, b int) int {
			return a * b
		},
		"dict": func(values ...interface{}) map[string]interface{} {
			if len(values)%2 != 0 {
				return nil
			}
			d := make(map[string]interface{}, len(values)/2)
			for i := 0; i < len(values); i += 2 {
				key, ok := values[i].(string)
				if !ok {
					continue
				}
				d[key] = values[i+1]
			}
			return d
		},
	}
}
