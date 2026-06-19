package logging

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
)

func Error(err error) slog.Attr {
	if err == nil {
		return slog.Any("error", nil)
	}
	return slog.String("error", err.Error())
}

// HumanBytes formats a byte count as a human-readable string (e.g. "1.5 MiB")
// for logging. The value is resolved lazily, so it costs nothing unless logged.
func HumanBytes(n int64) slog.Value {
	const unit = 1024
	if n < unit {
		return slog.StringValue(fmt.Sprintf("%d B", n))
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return slog.StringValue(fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp]))
}

type argsContextKey struct{}

func AttachArgs(ctx context.Context, args ...any) context.Context {
	existingArgs, _ := ctx.Value(argsContextKey{}).(*[]any)
	if existingArgs == nil {
		args := append([]any{}, args...)
		return context.WithValue(ctx, argsContextKey{}, &args)
	}

	*existingArgs = append(*existingArgs, args...)
	return ctx
}

type base64Bytes []byte

func (b base64Bytes) LogValue() slog.Value {
	return slog.StringValue(base64.StdEncoding.EncodeToString(b))
}

func Bytes(b []byte) slog.Value {
	return slog.AnyValue(base64Bytes(b))
}
