package templates

import (
        "html/template"
        "strings"
        "testing"
)

func TestSafeEq_CrossTypeNumeric(t *testing.T) {
        tests := []struct {
                name string
                a    interface{}
                b    interface{}
                want bool
        }{
                {"float64 vs int zero", float64(0), int(0), true},
                {"int vs float64 zero", int(0), float64(0), true},
                {"float64(2) vs int(2)", float64(2), int(2), true},
                {"float64(3) vs int(3)", float64(3), int(3), true},
                {"float64(2048) vs int(2048)", float64(2048), int(2048), true},
                {"float64(1) vs int(0)", float64(1), int(0), false},
                {"int(5) vs float64(10)", int(5), float64(10), false},
                {"float64(0) vs int(1)", float64(0), int(1), false},
                {"int32 vs float64", int32(42), float64(42), true},
                {"int64 vs float64", int64(100), float64(100), true},
                {"float32 vs int", float32(7), int(7), true},
                {"uint vs float64", uint(255), float64(255), true},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := safeEq(tt.a, tt.b)
                        if got != tt.want {
                                t.Errorf("safeEq(%v [%T], %v [%T]) = %v, want %v",
                                        tt.a, tt.a, tt.b, tt.b, got, tt.want)
                        }
                })
        }
}

func TestSafeEq_Variadic(t *testing.T) {
        if !safeEq(float64(2), int(1), int(2), int(3)) {
                t.Error("safeEq(2.0, 1, 2, 3) should be true (matches 2)")
        }
        if safeEq(float64(5), int(1), int(2), int(3)) {
                t.Error("safeEq(5.0, 1, 2, 3) should be false (no match)")
        }
        if !safeEq("hello", "world", "hello") {
                t.Error("safeEq('hello', 'world', 'hello') should be true")
        }
}

func TestSafeEq_Strings(t *testing.T) {
        tests := []struct {
                name string
                a, b interface{}
                want bool
        }{
                {"equal strings", "success", "success", true},
                {"different strings", "success", "error", false},
                {"empty strings", "", "", true},
                {"empty vs non-empty", "", "hello", false},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := safeEq(tt.a, tt.b)
                        if got != tt.want {
                                t.Errorf("safeEq(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
                        }
                })
        }
}

func TestSafeEq_Nil(t *testing.T) {
        if !safeEq(nil, nil) {
                t.Error("safeEq(nil, nil) should be true")
        }
        if safeEq(nil, int(0)) {
                t.Error("safeEq(nil, 0) should be false")
        }
        if safeEq("hello", nil) {
                t.Error("safeEq('hello', nil) should be false")
        }
}

func TestSafeNe_CrossTypeNumeric(t *testing.T) {
        if safeNe(float64(0), int(0)) {
                t.Error("safeNe(0.0, 0) should be false")
        }
        if !safeNe(float64(1), int(0)) {
                t.Error("safeNe(1.0, 0) should be true")
        }
        if safeNe(float64(2048), int(2048)) {
                t.Error("safeNe(2048.0, 2048) should be false")
        }
}

func TestGtCmp_CrossType(t *testing.T) {
        if !gtCmp(float64(10), int(5)) {
                t.Error("gtCmp(10.0, 5) should be true")
        }
        if gtCmp(float64(0), int(0)) {
                t.Error("gtCmp(0.0, 0) should be false")
        }
        if gtCmp(int(3), float64(5)) {
                t.Error("gtCmp(3, 5.0) should be false")
        }
}

func TestLtCmp_CrossType(t *testing.T) {
        if !ltCmp(int(5), float64(10)) {
                t.Error("ltCmp(5, 10.0) should be true")
        }
        if ltCmp(float64(10), int(5)) {
                t.Error("ltCmp(10.0, 5) should be false")
        }
}

func TestGeCmp_CrossType(t *testing.T) {
        if !geCmp(float64(10), int(10)) {
                t.Error("geCmp(10.0, 10) should be true")
        }
        if !geCmp(float64(11), int(10)) {
                t.Error("geCmp(11.0, 10) should be true")
        }
        if geCmp(float64(9), int(10)) {
                t.Error("geCmp(9.0, 10) should be false")
        }
}

func TestLeCmp_CrossType(t *testing.T) {
        if !leCmp(float64(10), int(10)) {
                t.Error("leCmp(10.0, 10) should be true")
        }
        if !leCmp(float64(9), int(10)) {
                t.Error("leCmp(9.0, 10) should be true")
        }
        if leCmp(float64(11), int(10)) {
                t.Error("leCmp(11.0, 10) should be false")
        }
}

func TestTemplateRender_MixedTypes(t *testing.T) {
        tmpl := template.Must(template.New("test").Funcs(FuncMap()).Parse(
                `{{if eq .floatVal 0}}ZERO{{else}}NONZERO{{end}}|` +
                        `{{if ne .floatVal 1}}NOT_ONE{{else}}IS_ONE{{end}}|` +
                        `{{if gt .floatVal 5}}GT5{{else}}LTE5{{end}}|` +
                        `{{if lt .intVal 100.0}}LT100{{else}}GTE100{{end}}`,
        ))

        tests := []struct {
                name     string
                data     map[string]interface{}
                expected string
        }{
                {
                        "float64 zero vs int literals",
                        map[string]interface{}{"floatVal": float64(0), "intVal": int(50)},
                        "ZERO|NOT_ONE|LTE5|LT100",
                },
                {
                        "float64 nonzero vs int literals",
                        map[string]interface{}{"floatVal": float64(10), "intVal": int(200)},
                        "NONZERO|NOT_ONE|GT5|GTE100",
                },
                {
                        "float64 one vs int literals",
                        map[string]interface{}{"floatVal": float64(1), "intVal": int(99)},
                        "NONZERO|IS_ONE|LTE5|LT100",
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        var buf strings.Builder
                        err := tmpl.Execute(&buf, tt.data)
                        if err != nil {
                                t.Fatalf("template execution failed: %v", err)
                        }
                        if buf.String() != tt.expected {
                                t.Errorf("got %q, want %q", buf.String(), tt.expected)
                        }
                })
        }
}

func TestTemplateRender_VariadicEq(t *testing.T) {
        tmpl := template.Must(template.New("test").Funcs(FuncMap()).Parse(
                `{{if eq .val 2 3}}MATCH{{else}}NO_MATCH{{end}}`,
        ))

        tests := []struct {
                name     string
                val      interface{}
                expected string
        }{
                {"float64(2) matches int 2", float64(2), "MATCH"},
                {"float64(3) matches int 3", float64(3), "MATCH"},
                {"float64(1) no match", float64(1), "NO_MATCH"},
                {"int(2) matches", int(2), "MATCH"},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        var buf strings.Builder
                        err := tmpl.Execute(&buf, map[string]interface{}{"val": tt.val})
                        if err != nil {
                                t.Fatalf("template execution failed: %v", err)
                        }
                        if buf.String() != tt.expected {
                                t.Errorf("got %q, want %q", buf.String(), tt.expected)
                        }
                })
        }
}

func TestTemplateRender_NoPanic(t *testing.T) {
        tmpl := template.Must(template.New("test").Funcs(FuncMap()).Parse(
                `{{if eq .f 0}}Z{{end}}{{if ne .f 1}}N{{end}}` +
                        `{{if gt .f 0}}G{{end}}{{if lt .f 100}}L{{end}}` +
                        `{{if ge .f 0}}GE{{end}}{{if le .f 100}}LE{{end}}`,
        ))

        vals := []interface{}{
                float64(0), float64(50), float64(100),
                int(0), int(50), int(100),
                int32(0), int64(50), float32(100),
                uint(0), uint(50),
        }

        for _, v := range vals {
                t.Run("", func(t *testing.T) {
                        var buf strings.Builder
                        err := tmpl.Execute(&buf, map[string]interface{}{"f": v})
                        if err != nil {
                                t.Fatalf("template panicked with %T(%v): %v", v, v, err)
                        }
                })
        }
}

func TestToFloat64(t *testing.T) {
        tests := []struct {
                input interface{}
                want  float64
        }{
                {int(42), 42},
                {int32(42), 42},
                {int64(42), 42},
                {float32(42.5), 42.5},
                {float64(42.5), 42.5},
                {uint(42), 42},
                {nil, 0},
                {"not a number", 0},
        }
        for _, tt := range tests {
                got := toFloat64(tt.input)
                if got != tt.want {
                        t.Errorf("toFloat64(%v [%T]) = %v, want %v", tt.input, tt.input, got, tt.want)
                }
        }
}
