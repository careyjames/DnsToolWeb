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
        m := template.FuncMap{}
        mergeFuncs(m, dateTimeFuncs())
        mergeFuncs(m, numberFuncs())
        mergeFuncs(m, stringFuncs())
        mergeFuncs(m, safeFuncs())
        mergeFuncs(m, mapFuncs())
        mergeFuncs(m, sliceFuncs())
        mergeFuncs(m, comparisonFuncs())
        mergeFuncs(m, displayFuncs())
        return m
}

func mergeFuncs(dst, src template.FuncMap) {
        for k, v := range src {
                dst[k] = v
        }
}

func dateTimeFuncs() template.FuncMap {
        return template.FuncMap{
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
        }
}

func numberFuncs() template.FuncMap {
        return template.FuncMap{
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
                "percent": func(value, total interface{}) float64 {
                        v := toFloat64(value)
                        t := toFloat64(total)
                        if t == 0 {
                                return 0
                        }
                        return math.Round(v/t*1000) / 10
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
        }
}

func stringFuncs() template.FuncMap {
        return template.FuncMap{
                "upper":     strings.ToUpper,
                "lower":     strings.ToLower,
                "title":     strings.Title,
                "contains":  strings.Contains,
                "hasPrefix": strings.HasPrefix,
                "hasSuffix": strings.HasSuffix,
                "join":      strings.Join,
                "trimSpace": strings.TrimSpace,
                "truncate": func(length int, s string) string {
                        if len(s) <= length {
                                return s
                        }
                        return s[:length] + "..."
                },
                "replace": func(old, new, s string) string {
                        return strings.ReplaceAll(s, old, new)
                },
                "urlEncode": func(s string) string {
                        return url.QueryEscape(s)
                },
                "bimiProxyURL": func(logoURL string) template.URL {
                        return template.URL("/proxy/bimi-logo?url=" + url.QueryEscape(logoURL))
                },
        }
}

func safeFuncs() template.FuncMap {
        return template.FuncMap{
                "safeHTML": func(s string) template.HTML {
                        return template.HTML(s)
                },
                "safeURL": func(s string) template.URL {
                        return template.URL(s)
                },
                "safeAttr": func(s string) template.HTMLAttr {
                        return template.HTMLAttr(s)
                },
                "safeJS": func(s string) template.JS {
                        return template.JS(s)
                },
        }
}

func mapFuncs() template.FuncMap {
        return template.FuncMap{
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
                        switch s := v.(type) {
                        case []interface{}:
                                return s
                        case []string:
                                result := make([]interface{}, len(s))
                                for i, str := range s {
                                        result[i] = str
                                }
                                return result
                        case []map[string]interface{}:
                                result := make([]interface{}, len(s))
                                for i, m := range s {
                                        result[i] = m
                                }
                                return result
                        default:
                                return nil
                        }
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
                "isMap": func(v interface{}) bool {
                        _, ok := v.(map[string]interface{})
                        return ok
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
        }
}

func sliceFuncs() template.FuncMap {
        return template.FuncMap{
                "list": func(values ...interface{}) []interface{} {
                        return values
                },
                "seq": func(start, end int) []int {
                        var result []int
                        for i := start; i <= end; i++ {
                                result = append(result, i)
                        }
                        return result
                },
                "isSlice": func(v interface{}) bool {
                        switch v.(type) {
                        case []interface{}, []string, []int, []float64:
                                return true
                        default:
                                return false
                        }
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
        }
}

func comparisonFuncs() template.FuncMap {
        return template.FuncMap{
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
                "isNil": func(v interface{}) bool {
                        return v == nil
                },
                "notNil": func(v interface{}) bool {
                        return v != nil
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
        }
}

func displayFuncs() template.FuncMap {
        return template.FuncMap{
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
                "countryFlag": func(code string) string {
                        if len(code) != 2 {
                                return ""
                        }
                        code = strings.ToUpper(code)
                        r1 := rune(0x1F1E6 + int(code[0]) - int('A'))
                        r2 := rune(0x1F1E6 + int(code[1]) - int('A'))
                        return string([]rune{r1, r2})
                },
                "staticURL": func(path string) string {
                        return "/static/" + path
                },
                "staticVersionURL": func(path, version string) string {
                        return "/static/" + path + "?v=" + version
                },
                "toJSON": func(v interface{}) string {
                        b, err := json.Marshal(v)
                        if err != nil {
                                return "{}"
                        }
                        return string(b)
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
                "pluralize": func(count interface{}, singular, plural string) string {
                        n := toFloat64(count)
                        if n == 1 {
                                return singular
                        }
                        return plural
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
