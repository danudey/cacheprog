package storage

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckRemoteURLScheme(t *testing.T) {
	tests := []struct {
		name          string
		rawURL        string
		allowInsecure bool
		wantErr       bool
	}{
		{name: "empty is allowed", rawURL: "", allowInsecure: false, wantErr: false},
		{name: "https is allowed", rawURL: "https://example.com", allowInsecure: false, wantErr: false},
		{name: "minio+https is allowed", rawURL: "minio+https://example.com:9000", allowInsecure: false, wantErr: false},
		{name: "http is rejected by default", rawURL: "http://example.com", allowInsecure: false, wantErr: true},
		{name: "minio+http is rejected by default", rawURL: "minio+http://example.com:9000", allowInsecure: false, wantErr: true},
		{name: "http is allowed with override", rawURL: "http://example.com", allowInsecure: true, wantErr: false},
		{name: "minio+http is allowed with override", rawURL: "minio+http://example.com:9000", allowInsecure: true, wantErr: false},
		{name: "scheme casing is ignored", rawURL: "HTTP://example.com", allowInsecure: false, wantErr: true},
		{name: "parse error is rejected", rawURL: "http://exa mple.com", allowInsecure: true, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := checkRemoteURLScheme("test endpoint", tt.rawURL, tt.allowInsecure)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "test endpoint")
				assert.Nil(t, u)
				return
			}
			require.NoError(t, err)
			if tt.rawURL == "" {
				assert.Nil(t, u, "an empty URL means not configured")
				return
			}
			require.NotNil(t, u)
			assert.Equal(t, "example.com", u.Hostname())
			assert.Equal(t, strings.ToLower(u.Scheme), u.Scheme, "the scheme must come back lower-cased")
		})
	}
}
