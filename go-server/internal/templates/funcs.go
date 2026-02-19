package templates

import (
        "encoding/json"
        "fmt"
        "html/template"
        "math"
        "net/url"
        "strconv"
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

func formatTimeValue(t interface{}, layout, defaultVal string) string {
        switch v := t.(type) {
        case time.Time:
                return v.Format(layout)
        case string:
                return v
        default:
                return defaultVal
        }
}

func formatDate(t interface{}) string {
        return formatTimeValue(t, "Jan 02, 2006 15:04 UTC", fmt.Sprintf("%v", t))
}

func formatDateShort(t interface{}) string {
        return formatTimeValue(t, "2006-01-02", "")
}

func formatTime(t interface{}) string {
        return formatTimeValue(t, "15:04:05", "")
}

func formatDateTime(t interface{}) string {
        return formatTimeValue(t, "2006-01-02 15:04:05", "")
}

func formatDateMonthDay(t interface{}) string {
        return formatTimeValue(t, "01/02", "")
}

func formatDuration(d interface{}) string {
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
}

func dateTimeFuncs() template.FuncMap {
        return template.FuncMap{
                "formatDate":         formatDate,
                "formatDateShort":    formatDateShort,
                "formatTime":         formatTime,
                "formatDateTime":     formatDateTime,
                "formatDateMonthDay": formatDateMonthDay,
                "formatDuration":     formatDuration,
        }
}

func formatFloat(precision int, f interface{}) string {
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
}

func successRate(successful, total interface{}) string {
        s := toFloat64(successful)
        t := toFloat64(total)
        if t == 0 {
                return "0"
        }
        return fmt.Sprintf("%.1f", (s/t)*100)
}

func percent(value, total interface{}) float64 {
        v := toFloat64(value)
        t := toFloat64(total)
        if t == 0 {
                return 0
        }
        return math.Round(v/t*1000) / 10
}

func addInt(a, b int) int    { return a + b }
func subInt(a, b int) int    { return a - b }
func mulInt(a, b int) int    { return a * b }
func maxInt(a, b int) int {
        if a > b {
                return a
        }
        return b
}
func minInt(a, b int) int {
        if a < b {
                return a
        }
        return b
}

func divFloat(a, b float64) float64 {
        if b == 0 {
                return 0
        }
        return a / b
}

func modInt(a, b int) int {
        if b == 0 {
                return 0
        }
        return a % b
}

func intDiv(a, b interface{}) int {
        ai := int(toFloat64(a))
        bi := int(toFloat64(b))
        if bi == 0 {
                return 0
        }
        return ai / bi
}

func maxIntIface(a, b interface{}) int {
        ai := int(toFloat64(a))
        bi := int(toFloat64(b))
        if ai > bi {
                return ai
        }
        return bi
}

func numberFuncs() template.FuncMap {
        return template.FuncMap{
                "formatFloat": formatFloat,
                "successRate": successRate,
                "percent":     percent,
                "add":         addInt,
                "sub":         subInt,
                "mul":         mulInt,
                "divf":        divFloat,
                "mod":         modInt,
                "max":         maxInt,
                "min":         minInt,
                "intDiv":      intDiv,
                "maxInt":      maxIntIface,
        }
}

func truncateStr(length int, s string) string {
        if len(s) <= length {
                return s
        }
        return s[:length] + "..."
}

func substrStr(start, length int, s string) string {
        if start >= len(s) {
                return ""
        }
        end := start + length
        if end > len(s) {
                end = len(s)
        }
        return s[start:end]
}

func replaceStr(old, new, s string) string {
        return strings.ReplaceAll(s, old, new)
}

func urlEncode(s string) string {
        return url.QueryEscape(s)
}

func bimiProxyURL(logoURL string) template.URL {
        return template.URL("/proxy/bimi-logo?url=" + url.QueryEscape(logoURL))
}

func stringFuncs() template.FuncMap {
        return template.FuncMap{
                "upper":        strings.ToUpper,
                "lower":        strings.ToLower,
                "title":        strings.Title,
                "contains":     strings.Contains,
                "hasPrefix":    strings.HasPrefix,
                "hasSuffix":    strings.HasSuffix,
                "join":         strings.Join,
                "trimSpace":    strings.TrimSpace,
                "truncate":     truncateStr,
                "substr":       substrStr,
                "replace":      replaceStr,
                "urlEncode":    urlEncode,
                "bimiProxyURL": bimiProxyURL,
        }
}

func safeFuncs() template.FuncMap {
        return template.FuncMap{
                "safeHTML": func(s string) template.HTML { return template.HTML(s) },
                "safeURL":  func(s string) template.URL { return template.URL(s) },
                "safeAttr": func(s string) template.HTMLAttr { return template.HTMLAttr(s) },
                "safeJS":   func(s string) template.JS { return template.JS(s) },
        }
}

func mapGet(key string, m map[string]interface{}) interface{} {
        if m == nil {
                return nil
        }
        return m[key]
}

func mapGetStr(key string, m map[string]interface{}) string {
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
}

func mapGetInt(key string, m map[string]interface{}) int {
        if m == nil {
                return 0
        }
        v, ok := m[key]
        if !ok || v == nil {
                return 0
        }
        switch n := v.(type) {
        case int:
                return n
        case int64:
                return int(n)
        case float64:
                return int(n)
        default:
                return 0
        }
}

func mapGetFloat(key string, m map[string]interface{}) float64 {
        if m == nil {
                return 0
        }
        return toFloat64(m[key])
}

func mapGetBool(key string, m map[string]interface{}) bool {
        if m == nil {
                return false
        }
        v, ok := m[key]
        if !ok || v == nil {
                return false
        }
        b, ok := v.(bool)
        return ok && b
}

func mapGetMap(key string, m map[string]interface{}) map[string]interface{} {
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
}

func mapGetSlice(key string, m map[string]interface{}) []interface{} {
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
}

func mapKeys(m map[string]interface{}) []string {
        if m == nil {
                return nil
        }
        keys := make([]string, 0, len(m))
        for k := range m {
                keys = append(keys, k)
        }
        return keys
}

func dict(values ...interface{}) map[string]interface{} {
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
}

func isMap(v interface{}) bool {
        _, ok := v.(map[string]interface{})
        return ok
}

func toMap(v interface{}) map[string]interface{} {
        if v == nil {
                return nil
        }
        m, ok := v.(map[string]interface{})
        if !ok {
                return nil
        }
        return m
}

func mapFuncs() template.FuncMap {
        return template.FuncMap{
                "mapGet":      mapGet,
                "mapGetStr":   mapGetStr,
                "mapGetInt":   mapGetInt,
                "mapGetFloat": mapGetFloat,
                "mapGetBool":  mapGetBool,
                "mapGetMap":   mapGetMap,
                "mapGetSlice": mapGetSlice,
                "mapKeys":     mapKeys,
                "dict":        dict,
                "isMap":       isMap,
                "toMap":       toMap,
        }
}

func listSlice(values ...interface{}) []interface{} {
        return values
}

func seq(start, end int) []int {
        var result []int
        for i := start; i <= end; i++ {
                result = append(result, i)
        }
        return result
}

func isSlice(v interface{}) bool {
        switch v.(type) {
        case []interface{}, []string, []int, []float64:
                return true
        default:
                return false
        }
}

func sliceFrom(start int, s []interface{}) []interface{} {
        if start >= len(s) {
                return nil
        }
        return s[start:]
}

func sliceIndex(i int, s []interface{}) interface{} {
        if i < 0 || i >= len(s) {
                return nil
        }
        return s[i]
}

func toInt(v interface{}) int {
        switch n := v.(type) {
        case int:
                return n
        case int32:
                return int(n)
        case int64:
                return int(n)
        case float64:
                return int(n)
        case float32:
                return int(n)
        default:
                return 0
        }
}

func toStringSlice(v interface{}) []string {
        if v == nil {
                return nil
        }
        switch s := v.(type) {
        case []string:
                return s
        case []interface{}:
                result := make([]string, 0, len(s))
                for _, item := range s {
                        if str, ok := item.(string); ok {
                                result = append(result, str)
                        }
                }
                return result
        default:
                return nil
        }
}

func toMapSlice(v interface{}) []map[string]interface{} {
        if v == nil {
                return nil
        }
        switch s := v.(type) {
        case []map[string]interface{}:
                return s
        case []interface{}:
                result := make([]map[string]interface{}, 0, len(s))
                for _, item := range s {
                        if m, ok := item.(map[string]interface{}); ok {
                                result = append(result, m)
                        }
                }
                return result
        default:
                return nil
        }
}

func sliceFuncs() template.FuncMap {
        return template.FuncMap{
                "list":          listSlice,
                "seq":           seq,
                "isSlice":       isSlice,
                "sliceFrom":     sliceFrom,
                "sliceIndex":    sliceIndex,
                "toInt":         toInt,
                "toStringSlice": toStringSlice,
                "toMapSlice":    toMapSlice,
        }
}

func isNumeric(v interface{}) bool {
        switch v.(type) {
        case int, int8, int16, int32, int64,
                uint, uint8, uint16, uint32, uint64,
                float32, float64:
                return true
        default:
                return false
        }
}

func safeEqual(a, b interface{}) bool {
        if isNumeric(a) && isNumeric(b) {
                return toFloat64(a) == toFloat64(b)
        }
        if a == nil || b == nil {
                return a == b
        }
        return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

func safeEq(arg1 interface{}, args ...interface{}) bool {
        for _, arg2 := range args {
                if safeEqual(arg1, arg2) {
                        return true
                }
        }
        return false
}

func safeNe(a, b interface{}) bool { return !safeEqual(a, b) }

func gtCmp(a, b interface{}) bool  { return toFloat64(a) > toFloat64(b) }
func gteCmp(a, b interface{}) bool { return toFloat64(a) >= toFloat64(b) }
func ltCmp(a, b interface{}) bool  { return toFloat64(a) < toFloat64(b) }
func lteCmp(a, b interface{}) bool { return toFloat64(a) <= toFloat64(b) }
func geCmp(a, b interface{}) bool  { return toFloat64(a) >= toFloat64(b) }
func leCmp(a, b interface{}) bool  { return toFloat64(a) <= toFloat64(b) }
func isNil(v interface{}) bool     { return v == nil }
func notNil(v interface{}) bool    { return v != nil }

func defaultVal(defaultV, val interface{}) interface{} {
        if val == nil {
                return defaultV
        }
        if s, ok := val.(string); ok && s == "" {
                return defaultV
        }
        return val
}

func coalesce(vals ...interface{}) interface{} {
        for _, v := range vals {
                if v == nil {
                        continue
                }
                if s, ok := v.(string); ok && s == "" {
                        continue
                }
                return v
        }
        return nil
}

func comparisonFuncs() template.FuncMap {
        return template.FuncMap{
                "eq":       safeEq,
                "ne":       safeNe,
                "gt":       gtCmp,
                "gte":      gteCmp,
                "lt":       ltCmp,
                "lte":      lteCmp,
                "ge":       geCmp,
                "le":       leCmp,
                "isNil":    isNil,
                "notNil":   notNil,
                "default":  defaultVal,
                "coalesce": coalesce,
        }
}

const bgDanger = "bg-danger"

var statusBadgeClassMap = map[string]string{
        "success":  "bg-success",
        "warning":  "bg-warning",
        "info":     "bg-info",
        "danger":   bgDanger,
        "error":    bgDanger,
        "critical": bgDanger,
}

var statusColorMap = map[string]string{
        "success":  "success",
        "warning":  "warning",
        "partial":  "warning",
        "error":    "danger",
        "danger":   "danger",
        "critical": "danger",
        "info":     "info",
}

func statusBadgeClass(status string) string {
        if c, ok := statusBadgeClassMap[strings.ToLower(status)]; ok {
                return c
        }
        return "bg-secondary"
}

func statusColor(status string) string {
        if c, ok := statusColorMap[strings.ToLower(status)]; ok {
                return c
        }
        return "secondary"
}

func countryFlag(code string) string {
        if len(code) != 2 {
                return ""
        }
        code = strings.ToUpper(code)
        r1 := rune(0x1F1E6 + int(code[0]) - int('A'))
        r2 := rune(0x1F1E6 + int(code[1]) - int('A'))
        return string([]rune{r1, r2})
}

func staticURL(path string) string {
        return "/static/" + path
}

func staticVersionURL(path, version string) string {
        return "/static/" + path + "?v=" + version
}

func toJSON(v interface{}) string {
        b, err := json.Marshal(v)
        if err != nil {
                return "{}"
        }
        return string(b)
}

func toStr(v interface{}) string {
        if v == nil {
                return ""
        }
        s, ok := v.(string)
        if ok {
                return s
        }
        return fmt.Sprintf("%v", v)
}

func pluralize(count interface{}, singular, plural string) string {
        n := toFloat64(count)
        if n == 1 {
                return singular
        }
        return plural
}

func htmlComment(s string) template.HTML {
        clean := strings.ReplaceAll(s, "--", "\u2014")
        return template.HTML("<!--\n" + clean + "\n-->")
}

func displayFuncs() template.FuncMap {
        return template.FuncMap{
                "statusBadgeClass": statusBadgeClass,
                "statusColor":      statusColor,
                "countryFlag":      countryFlag,
                "staticURL":        staticURL,
                "staticVersionURL": staticVersionURL,
                "toJSON":           toJSON,
                "toStr":            toStr,
                "pluralize":        pluralize,
                "htmlComment":      htmlComment,
        }
}

func toFloat64(v interface{}) float64 {
        switch n := v.(type) {
        case int:
                return float64(n)
        case int8:
                return float64(n)
        case int16:
                return float64(n)
        case int32:
                return float64(n)
        case int64:
                return float64(n)
        case uint:
                return float64(n)
        case uint8:
                return float64(n)
        case uint16:
                return float64(n)
        case uint32:
                return float64(n)
        case uint64:
                return float64(n)
        case float32:
                return float64(n)
        case float64:
                return n
        case string:
                if f, err := strconv.ParseFloat(n, 64); err == nil {
                        return f
                }
                return 0
        default:
                return 0
        }
}
