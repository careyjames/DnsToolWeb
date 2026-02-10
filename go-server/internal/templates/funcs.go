package templates

import (
        "encoding/json"
        "fmt"
        "html/template"
        "math"
        "net/url"
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
                "formatDate": func(t interface{}) string {
                        switch v := t.(type) {
                        case time.Time:
                                return v.Format("Jan 02, 2006 15:04 UTC")
                        case string:
                                return v
                        default:
                                return fmt.Sprintf("%v", t)
                        }
                },
                "formatDateShort": func(t interface{}) string {
                        switch v := t.(type) {
                        case time.Time:
                                return v.Format("2006-01-02")
                        case string:
                                return v
                        default:
                                return ""
                        }
                },
                "formatTime": func(t interface{}) string {
                        switch v := t.(type) {
                        case time.Time:
                                return v.Format("15:04:05")
                        case string:
                                return v
                        default:
                                return ""
                        }
                },
                "formatDateTime": func(t interface{}) string {
                        switch v := t.(type) {
                        case time.Time:
                                return v.Format("2006-01-02 15:04:05")
                        case string:
                                return v
                        default:
                                return ""
                        }
                },
                "formatDateMonthDay": func(t interface{}) string {
                        switch v := t.(type) {
                        case time.Time:
                                return v.Format("01/02")
                        case string:
                                return v
                        default:
                                return ""
                        }
                },
                "formatDuration": func(d interface{}) string {
                        switch v := d.(type) {
                        case float64:
                                if v < 1.0 {
                                        return fmt.Sprintf("%.0fms", v*1000)
                                }
                                return fmt.Sprintf("%.1fs", v)
                        case float32:
                                return fmt.Sprintf("%.1fs", v)
                        default:
                                return fmt.Sprintf("%v", d)
                        }
                },
                "formatFloat": func(precision int, f interface{}) string {
                        switch v := f.(type) {
                        case float64:
                                return fmt.Sprintf("%.*f", precision, v)
                        case float32:
                                return fmt.Sprintf("%.*f", precision, float64(v))
                        case int:
                                return fmt.Sprintf("%.*f", precision, float64(v))
                        case int64:
                                return fmt.Sprintf("%.*f", precision, float64(v))
                        default:
                                return fmt.Sprintf("%v", f)
                        }
                },
                "successRate": func(successful, total interface{}) string {
                        s := toFloat64(successful)
                        t := toFloat64(total)
                        if t == 0 {
                                return "0"
                        }
                        return fmt.Sprintf("%.1f", (s/t)*100)
                },
                "upper": strings.ToUpper,
                "lower": strings.ToLower,
                "title": strings.Title,
                "contains": strings.Contains,
                "hasPrefix": strings.HasPrefix,
                "hasSuffix": strings.HasSuffix,
                "join":      strings.Join,
                "trimSpace": strings.TrimSpace,
                "safeHTML": func(s string) template.HTML {
                        return template.HTML(s)
                },
                "safeURL": func(s string) template.URL {
                        return template.URL(s)
                },
                "safeAttr": func(s string) template.HTMLAttr {
                        return template.HTMLAttr(s)
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
                "divf": func(a, b float64) float64 {
                        if b == 0 {
                                return 0
                        }
                        return a / b
                },
                "mod": func(a, b int) int {
                        if b == 0 {
                                return 0
                        }
                        return a % b
                },
                "max": func(a, b int) int {
                        if a > b {
                                return a
                        }
                        return b
                },
                "min": func(a, b int) int {
                        if a < b {
                                return a
                        }
                        return b
                },
                "seq": func(start, end int) []int {
                        var result []int
                        for i := start; i <= end; i++ {
                                result = append(result, i)
                        }
                        return result
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
                "list": func(values ...interface{}) []interface{} {
                        return values
                },
                "default": func(defaultVal, val interface{}) interface{} {
                        if val == nil {
                                return defaultVal
                        }
                        if s, ok := val.(string); ok && s == "" {
                                return defaultVal
                        }
                        return val
                },
                "coalesce": func(vals ...interface{}) interface{} {
                        for _, v := range vals {
                                if v != nil {
                                        if s, ok := v.(string); ok && s == "" {
                                                continue
                                        }
                                        return v
                                }
                        }
                        return nil
                },
                "statusBadgeClass": func(status string) string {
                        switch strings.ToLower(status) {
                        case "success":
                                return "bg-success"
                        case "warning":
                                return "bg-warning"
                        case "info":
                                return "bg-info"
                        case "danger", "error", "critical":
                                return "bg-danger"
                        default:
                                return "bg-secondary"
                        }
                },
                "staticURL": func(path string) string {
                        return "/static/" + path
                },
                "staticVersionURL": func(path, version string) string {
                        return "/static/" + path + "?v=" + version
                },
                "urlEncode": func(s string) string {
                        return url.QueryEscape(s)
                },
                "toJSON": func(v interface{}) string {
                        b, err := json.Marshal(v)
                        if err != nil {
                                return "{}"
                        }
                        return string(b)
                },
                "truncate": func(length int, s string) string {
                        if len(s) <= length {
                                return s
                        }
                        return s[:length] + "..."
                },
                "isMap": func(v interface{}) bool {
                        _, ok := v.(map[string]interface{})
                        return ok
                },
                "isSlice": func(v interface{}) bool {
                        switch v.(type) {
                        case []interface{}, []string, []int, []float64:
                                return true
                        default:
                                return false
                        }
                },
                "isNil": func(v interface{}) bool {
                        return v == nil
                },
                "notNil": func(v interface{}) bool {
                        return v != nil
                },
                "mapGet": func(key string, m map[string]interface{}) interface{} {
                        if m == nil {
                                return nil
                        }
                        return m[key]
                },
                "mapGetStr": func(key string, m map[string]interface{}) string {
                        if m == nil {
                                return ""
                        }
                        v, ok := m[key]
                        if !ok || v == nil {
                                return ""
                        }
                        s, ok := v.(string)
                        if !ok {
                                return fmt.Sprintf("%v", v)
                        }
                        return s
                },
                "mapGetFloat": func(key string, m map[string]interface{}) float64 {
                        if m == nil {
                                return 0
                        }
                        return toFloat64(m[key])
                },
                "mapGetBool": func(key string, m map[string]interface{}) bool {
                        if m == nil {
                                return false
                        }
                        v, ok := m[key]
                        if !ok || v == nil {
                                return false
                        }
                        b, ok := v.(bool)
                        return ok && b
                },
                "mapGetMap": func(key string, m map[string]interface{}) map[string]interface{} {
                        if m == nil {
                                return nil
                        }
                        v, ok := m[key]
                        if !ok || v == nil {
                                return nil
                        }
                        sub, ok := v.(map[string]interface{})
                        if !ok {
                                return nil
                        }
                        return sub
                },
                "mapGetSlice": func(key string, m map[string]interface{}) []interface{} {
                        if m == nil {
                                return nil
                        }
                        v, ok := m[key]
                        if !ok || v == nil {
                                return nil
                        }
                        sl, ok := v.([]interface{})
                        if !ok {
                                return nil
                        }
                        return sl
                },
                "gt": func(a, b interface{}) bool {
                        return toFloat64(a) > toFloat64(b)
                },
                "gte": func(a, b interface{}) bool {
                        return toFloat64(a) >= toFloat64(b)
                },
                "lt": func(a, b interface{}) bool {
                        return toFloat64(a) < toFloat64(b)
                },
                "lte": func(a, b interface{}) bool {
                        return toFloat64(a) <= toFloat64(b)
                },
                "pluralize": func(count interface{}, singular, plural string) string {
                        n := toFloat64(count)
                        if n == 1 {
                                return singular
                        }
                        return plural
                },
                "percent": func(value, total interface{}) float64 {
                        v := toFloat64(value)
                        t := toFloat64(total)
                        if t == 0 {
                                return 0
                        }
                        return math.Round(v/t*1000) / 10
                },
                "replace": func(old, new, s string) string {
                        return strings.ReplaceAll(s, old, new)
                },
                "mapKeys": func(m map[string]interface{}) []string {
                        if m == nil {
                                return nil
                        }
                        keys := make([]string, 0, len(m))
                        for k := range m {
                                keys = append(keys, k)
                        }
                        return keys
                },
                "intDiv": func(a, b interface{}) int {
                        ai := int(toFloat64(a))
                        bi := int(toFloat64(b))
                        if bi == 0 {
                                return 0
                        }
                        return ai / bi
                },
                "maxInt": func(a, b interface{}) int {
                        ai := int(toFloat64(a))
                        bi := int(toFloat64(b))
                        if ai > bi {
                                return ai
                        }
                        return bi
                },
                "sliceFrom": func(start int, s []interface{}) []interface{} {
                        if start >= len(s) {
                                return nil
                        }
                        return s[start:]
                },
                "sliceIndex": func(i int, s []interface{}) interface{} {
                        if i < 0 || i >= len(s) {
                                return nil
                        }
                        return s[i]
                },
                "toMap": func(v interface{}) map[string]interface{} {
                        if v == nil {
                                return nil
                        }
                        m, ok := v.(map[string]interface{})
                        if !ok {
                                return nil
                        }
                        return m
                },
                "toStr": func(v interface{}) string {
                        if v == nil {
                                return ""
                        }
                        s, ok := v.(string)
                        if ok {
                                return s
                        }
                        return fmt.Sprintf("%v", v)
                },
                "statusColor": func(status string) string {
                        switch strings.ToLower(status) {
                        case "success":
                                return "success"
                        case "warning", "partial":
                                return "warning"
                        case "error", "danger", "critical":
                                return "danger"
                        case "info":
                                return "info"
                        default:
                                return "secondary"
                        }
                },
                "safeJS": func(s string) template.JS {
                        return template.JS(s)
                },
        }
}

func toFloat64(v interface{}) float64 {
        switch n := v.(type) {
        case int:
                return float64(n)
        case int32:
                return float64(n)
        case int64:
                return float64(n)
        case float32:
                return float64(n)
        case float64:
                return n
        default:
                return 0
        }
}
