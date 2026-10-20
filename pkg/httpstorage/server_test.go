package httpstorage

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/platacard/cacheprog/internal/app/cacheprog"
	"github.com/platacard/cacheprog/internal/infra/storage"
)

func TestServer_Get(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		remoteStorage := NewMockRemoteStorage(ctrl)
		handler := NewServer(remoteStorage)

		server := httptest.NewServer(handler)
		t.Cleanup(server.Close)

		actionID := []byte("test-action")
		content := []byte("test-content")
		outputID := []byte("test-output-id")
		modTime := time.Now().Truncate(time.Second).UTC()

		remoteStorage.EXPECT().Get(gomock.Any(), &cacheprog.GetRequest{
			ActionID: actionID,
		}).Return(&cacheprog.GetResponse{
			OutputID:             outputID,
			ModTime:              modTime,
			Size:                 int64(len(content)),
			Body:                 io.NopCloser(bytes.NewReader(content)),
			CompressionAlgorithm: "test-compression-algorithm",
			UncompressedSize:     int64(len(content)) * 2,
		}, nil)

		req, err := storage.NewGetRequest(context.Background(), server.URL, &cacheprog.GetRequest{
			ActionID: actionID,
		})
		require.NoError(t, err)

		resp, err := http.DefaultClient.Do(req)
		t.Cleanup(func() {
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
		})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		parsedResp, err := storage.ParseGetResponse(resp)
		require.NoError(t, err)
		require.Equal(t, outputID, parsedResp.OutputID)
		require.Equal(t, modTime, parsedResp.ModTime)
		require.Equal(t, int64(len(content)), parsedResp.Size)
		require.Equal(t, "test-compression-algorithm", parsedResp.CompressionAlgorithm)
		require.Equal(t, int64(len(content))*2, parsedResp.UncompressedSize)

		body, err := io.ReadAll(parsedResp.Body)
		require.NoError(t, err)
		require.Equal(t, content, body)
	})

	t.Run("not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		remoteStorage := NewMockRemoteStorage(ctrl)
		handler := NewServer(remoteStorage)

		server := httptest.NewServer(handler)
		t.Cleanup(server.Close)

		remoteStorage.EXPECT().Get(gomock.Any(), &cacheprog.GetRequest{
			ActionID: []byte("test-action"),
		}).Return(nil, cacheprog.ErrNotFound)

		req, err := storage.NewGetRequest(context.Background(), server.URL, &cacheprog.GetRequest{
			ActionID: []byte("test-action"),
		})
		require.NoError(t, err)

		resp, err := http.DefaultClient.Do(req)
		t.Cleanup(func() {
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
		})
		require.NoError(t, err)
		require.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

func TestServer_Put(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		remoteStorage := NewMockRemoteStorage(ctrl)
		handler := NewServer(remoteStorage)

		server := httptest.NewServer(handler)
		t.Cleanup(server.Close)

		actionID := []byte("test-action")
		content := []byte("test-content")
		outputID := []byte("test-output-id")
		size := int64(len(content))
		md5sum := md5.Sum(content)
		sha256sum := sha256.Sum256(content)
		compressionAlgorithm := "test-compression-algorithm"
		uncompressedSize := int64(len(content)) * 2

		remoteStorage.EXPECT().Put(gomock.Any(), &putRequestMatcher{
			putRequest: &cacheprog.PutRequest{
				ActionID:             actionID,
				OutputID:             outputID,
				Size:                 size,
				MD5Sum:               md5sum[:],
				Sha256Sum:            sha256sum[:],
				CompressionAlgorithm: compressionAlgorithm,
				UncompressedSize:     uncompressedSize,
			},
			body: content,
		}).Return(&cacheprog.PutResponse{}, nil)

		req, err := storage.NewPutRequest(context.Background(), server.URL, &cacheprog.PutRequest{
			ActionID:             actionID,
			OutputID:             outputID,
			Size:                 size,
			Body:                 bytes.NewReader(content),
			MD5Sum:               md5sum[:],
			Sha256Sum:            sha256sum[:],
			CompressionAlgorithm: compressionAlgorithm,
			UncompressedSize:     uncompressedSize,
		})
		require.NoError(t, err)

		resp, err := http.DefaultClient.Do(req)
		t.Cleanup(func() {
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
		})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

type putRequestMatcher struct {
	putRequest *cacheprog.PutRequest
	body       []byte
}

func (m *putRequestMatcher) Matches(x any) bool {
	req, ok := x.(*cacheprog.PutRequest)
	if !ok {
		return false
	}

	metaMatches := bytes.Equal(req.ActionID, m.putRequest.ActionID) &&
		bytes.Equal(req.OutputID, m.putRequest.OutputID) &&
		req.Size == m.putRequest.Size &&
		bytes.Equal(req.MD5Sum, m.putRequest.MD5Sum) &&
		bytes.Equal(req.Sha256Sum, m.putRequest.Sha256Sum) &&
		req.CompressionAlgorithm == m.putRequest.CompressionAlgorithm &&
		req.UncompressedSize == m.putRequest.UncompressedSize

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return false
	}

	return metaMatches && bytes.Equal(bodyBytes, m.body)
}

func (m *putRequestMatcher) String() string {
	return fmt.Sprintf("putRequest: %v, body: %v", m.putRequest, m.body)
}

func TestServer_Head(t *testing.T) {
	// headStorage implements both RemoteStorage and HeadRemoteStorage
	type headStorage struct {
		*MockRemoteStorage
		*MockHeadRemoteStorage
	}

	doHead := func(t *testing.T, remoteStorage RemoteStorage) int {
		t.Helper()
		server := httptest.NewServer(NewServer(remoteStorage))
		t.Cleanup(server.Close)

		req, err := storage.NewHeadRequest(context.Background(), server.URL, &cacheprog.HeadRequest{
			ActionID: []byte("test-action"),
		})
		require.NoError(t, err)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		return resp.StatusCode
	}

	for _, tc := range []struct {
		name   string
		err    error
		status int
	}{
		{name: "found", status: http.StatusOK},
		{name: "not found", err: cacheprog.ErrNotFound, status: http.StatusNotFound},
		{name: "error", err: fmt.Errorf("boom"), status: http.StatusInternalServerError},
	} {
		t.Run("head storage, "+tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			s := headStorage{NewMockRemoteStorage(ctrl), NewMockHeadRemoteStorage(ctrl)}

			var resp *cacheprog.HeadResponse
			if tc.err == nil {
				resp = &cacheprog.HeadResponse{}
			}
			s.MockHeadRemoteStorage.EXPECT().Head(gomock.Any(), &cacheprog.HeadRequest{
				ActionID: []byte("test-action"),
			}).Return(resp, tc.err)

			require.Equal(t, tc.status, doHead(t, s))
		})
	}

	t.Run("falls back to get", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		remoteStorage := NewMockRemoteStorage(ctrl)

		remoteStorage.EXPECT().Get(gomock.Any(), &cacheprog.GetRequest{
			ActionID: []byte("test-action"),
		}).Return(&cacheprog.GetResponse{
			Body: io.NopCloser(bytes.NewReader([]byte("test-content"))),
		}, nil)

		require.Equal(t, http.StatusOK, doHead(t, remoteStorage))
	})

	t.Run("falls back to get, not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		remoteStorage := NewMockRemoteStorage(ctrl)

		remoteStorage.EXPECT().Get(gomock.Any(), &cacheprog.GetRequest{
			ActionID: []byte("test-action"),
		}).Return(nil, cacheprog.ErrNotFound)

		require.Equal(t, http.StatusNotFound, doHead(t, remoteStorage))
	})
}
