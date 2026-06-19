package signing

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleManifest() *Manifest {
	return &Manifest{
		Version:          manifestVersion,
		AlgID:            AlgHMACSHA256,
		KeyID:            "key-1",
		ActionID:         []byte("action-id-bytes"),
		OutputID:         []byte("output-id-bytes"),
		CompressionAlgo:  "zstd",
		UncompressedSize: 4096,
		CompressedSize:   1234,
		CompressedSHA256: []byte("0123456789abcdef0123456789abcdef"),
	}
}

func TestManifest_MarshalUnmarshal_RoundTrip(t *testing.T) {
	m := sampleManifest()

	got, err := UnmarshalManifest(m.Marshal())
	require.NoError(t, err)
	assert.Equal(t, m, got)
}

func TestManifest_Marshal_Deterministic(t *testing.T) {
	m := sampleManifest()
	assert.Equal(t, m.Marshal(), m.Marshal())
}

func TestUnmarshalManifest_Errors(t *testing.T) {
	t.Run("truncated", func(t *testing.T) {
		b := sampleManifest().Marshal()
		_, err := UnmarshalManifest(b[:len(b)-3])
		require.Error(t, err)
	})

	t.Run("trailing bytes", func(t *testing.T) {
		b := append(sampleManifest().Marshal(), 0x00)
		_, err := UnmarshalManifest(b)
		require.ErrorContains(t, err, "trailing")
	})

	t.Run("bad version", func(t *testing.T) {
		m := sampleManifest()
		m.Version = 99
		_, err := UnmarshalManifest(m.Marshal())
		require.ErrorContains(t, err, "version")
	})

	t.Run("empty", func(t *testing.T) {
		_, err := UnmarshalManifest(nil)
		require.Error(t, err)
	})
}

func TestManifest_Marshal_FieldChangeChangesBytes(t *testing.T) {
	base := sampleManifest().Marshal()

	m := sampleManifest()
	m.OutputID = []byte("different-output")
	assert.NotEqual(t, base, m.Marshal())
}
