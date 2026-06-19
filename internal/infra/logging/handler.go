package logging

import (
	"cmp"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/charmbracelet/log"
)

// prefix is the program name, used to tag every log line with its source.
var prefix = filepath.Base(os.Args[0])

type Config struct {
	Level  slog.Level // logging level
	Output io.Writer  // logging output, stderr if not provided
}

func CreateHandler(w io.Writer, level slog.Level) slog.Handler {
	// charmbracelet/log's *log.Logger implements slog.Handler, so it can be
	// used directly as the backend for the slog API used throughout the code.
	// Its level constants are numerically identical to slog's.
	return &argsHandler{
		log.NewWithOptions(w, log.Options{
			Prefix:          prefix,
			Level:           log.Level(level),
			ReportCaller:    level == slog.LevelDebug,
			ReportTimestamp: true,
			TimeFormat:      time.TimeOnly,
		}),
	}
}

func ConfigureLogger(cfg Config) *slog.Logger {
	return slog.New(CreateHandler(cmp.Or(cfg.Output, io.Writer(os.Stderr)), cfg.Level))
}

type argsHandler struct {
	slog.Handler
}

func (h *argsHandler) Handle(ctx context.Context, record slog.Record) error {
	// AttachArgs stores the accumulated args as a *[]any so later calls can
	// append in place, so read back the same pointer type here.
	if args, _ := ctx.Value(argsContextKey{}).(*[]any); args != nil {
		record.Add(*args...)
	}

	// Unlike slog's built-in handlers, charmbracelet/log's slog.Handler does
	// not resolve slog.LogValuer attributes, so resolve them here to keep the
	// rendered output identical to the previous slog.TextHandler backend.
	resolved := slog.NewRecord(record.Time, record.Level, record.Message, record.PC)
	record.Attrs(func(a slog.Attr) bool {
		a.Value = a.Value.Resolve()
		resolved.AddAttrs(a)
		return true
	})
	return h.Handler.Handle(ctx, resolved)
}

func (h *argsHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &argsHandler{h.Handler.WithAttrs(attrs)}
}

func (h *argsHandler) WithGroup(name string) slog.Handler {
	return &argsHandler{h.Handler.WithGroup(name)}
}
