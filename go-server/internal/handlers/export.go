package handlers

import (
        "encoding/json"
        "fmt"
        "net/http"
        "time"

        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/dbq"

        "github.com/gin-gonic/gin"
)

type ExportHandler struct {
        DB *db.Database
}

func NewExportHandler(database *db.Database) *ExportHandler {
        return &ExportHandler{DB: database}
}

func (h *ExportHandler) ExportJSON(c *gin.Context) {
        timestamp := time.Now().UTC().Format("20060102_150405")
        filename := fmt.Sprintf("dns_tool_export_%s.ndjson", timestamp)

        c.Header("Content-Type", "application/x-ndjson")
        c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
        c.Status(http.StatusOK)

        ctx := c.Request.Context()
        perPage := int32(100)
        offset := int32(0)

        for {
                analyses, err := h.DB.Queries.ListSuccessfulAnalyses(ctx, dbq.ListSuccessfulAnalysesParams{
                        Limit:  perPage,
                        Offset: offset,
                })
                if err != nil || len(analyses) == 0 {
                        break
                }

                for _, a := range analyses {
                        var fullResults interface{}
                        if len(a.FullResults) > 0 {
                                json.Unmarshal(a.FullResults, &fullResults)
                        }

                        record := map[string]interface{}{
                                "id":                a.ID,
                                "domain":           a.Domain,
                                "ascii_domain":     a.AsciiDomain,
                                "created_at":       formatTimestampISO(a.CreatedAt),
                                "updated_at":       formatTimestampISO(a.UpdatedAt),
                                "analysis_duration": a.AnalysisDuration,
                                "country_code":     a.CountryCode,
                                "country_name":     a.CountryName,
                                "full_results":     fullResults,
                        }

                        line, _ := json.Marshal(record)
                        c.Writer.Write(line)
                        c.Writer.Write([]byte("\n"))
                }

                c.Writer.Flush()

                if len(analyses) < int(perPage) {
                        break
                }
                offset += perPage
        }
}
