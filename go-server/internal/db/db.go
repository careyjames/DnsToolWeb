package db

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"dnstool/internal/dbq"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Database struct {
	Pool    *pgxpool.Pool
	Queries *dbq.Queries
}

func Connect(databaseURL string) (*Database, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database URL: %w", err)
	}

	config.MaxConns = 10
	config.MinConns = 2
	config.MaxConnLifetime = 5 * time.Minute
	config.MaxConnIdleTime = 2 * time.Minute
	config.HealthCheckPeriod = 30 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	slog.Info("Database connected successfully")
	return &Database{
		Pool:    pool,
		Queries: dbq.New(pool),
	}, nil
}

func (d *Database) Close() {
	if d.Pool != nil {
		d.Pool.Close()
		slog.Info("Database connection closed")
	}
}

func (d *Database) HealthCheck(ctx context.Context) error {
	return d.Pool.Ping(ctx)
}
