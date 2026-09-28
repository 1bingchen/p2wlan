package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/internal/privatefile"
)

func TestUploadSupportLogsStoresCompressedPrivateBundle(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("LOG_UPLOAD_DIR", directory)
	server := NewServer(nil, nil, nil)

	bundle := supportLogBundle{
		SchemaVersion: supportLogSchemaVersion1,
		UploadedAt:    "2026-08-23T08:00:00Z",
		DeviceName:    "Mini",
		Platform:      "macos",
		Files: []supportLogBundleFile{{
			Name:    "p2wlan-daemon.log",
			Content: "direct_path_degraded\n",
		}},
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var body bytes.Buffer
	writer := gzip.NewWriter(&body)
	if _, err := writer.Write(encoded); err != nil {
		t.Fatalf("gzip.Write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("gzip.Close: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/support/logs", &body)
	req.Header.Set("Content-Encoding", "gzip")
	req = req.WithContext(context.WithValue(req.Context(), auth.UserClaimsKey, &auth.Claims{
		UserID: "user-1",
	}))
	recorder := httptest.NewRecorder()
	server.UploadSupportLogs(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("UploadSupportLogs: HTTP %d %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Success   bool   `json:"success"`
		UploadID  string `json:"upload_id"`
		Instances int    `json:"instances"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !response.Success || len(response.UploadID) != 24 {
		t.Fatalf("unexpected response: %+v", response)
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || filepath.Ext(entries[0].Name()) != ".gz" {
		t.Fatalf("expected one gzip upload, got %+v", entries)
	}
	if err := privatefile.Verify(filepath.Join(directory, entries[0].Name())); err != nil {
		t.Fatalf("upload access is not private: %v", err)
	}

	storedFile, err := os.Open(filepath.Join(directory, entries[0].Name()))
	if err != nil {
		t.Fatalf("Open upload: %v", err)
	}
	decompressed, err := gzip.NewReader(storedFile)
	if err != nil {
		t.Fatalf("stored gzip: %v", err)
	}
	storedBytes, err := io.ReadAll(decompressed)
	if err != nil {
		t.Fatalf("Read stored gzip: %v", err)
	}
	_ = decompressed.Close()
	_ = storedFile.Close()
	var stored storedSupportLogBundle
	if err := json.Unmarshal(storedBytes, &stored); err != nil {
		t.Fatalf("decode stored bundle: %v", err)
	}
	if stored.UploadID != response.UploadID || stored.UserID != "user-1" ||
		stored.Bundle.Files[0].Content != "direct_path_degraded\n" {
		t.Fatalf("unexpected stored bundle: %+v", stored)
	}
}

func TestUploadSupportLogsV2WithRoomInstances(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("LOG_UPLOAD_DIR", directory)
	server := NewServer(nil, nil, nil)

	roomHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	bundle := supportLogBundle{
		SchemaVersion: supportLogSchemaVersion2,
		UploadedAt:    "2026-09-09T08:00:00Z",
		DeviceName:    "MacBook",
		Platform:      "macos",
		Manifest: &supportLogManifest{
			TotalInstances: 2,
			NetworkIDs:     []string{"net-main", "room-123"},
			HasRoomLogs:    true,
		},
		Instances: []supportLogInstance{
			{
				InstanceType:  "main",
				NetworkID:     "net-main",
				BootID:        "boot-1",
				Log:           "main daemon log\n",
				StatusSummary: `{"virtual_ip":"10.20.0.1"}`,
			},
			{
				InstanceType:  "room",
				NetworkID:     "room-123",
				ProfileID:     roomHex,
				BootID:        "boot-2",
				Log:           "room daemon log\n",
				StatusSummary: `{"virtual_ip":"10.20.1.2"}`,
			},
		},
		Files: []supportLogBundleFile{
			{
				Name:    "p2wlan-daemon.log",
				Content: "main log file\n",
			},
			{
				Name:    "rooms/" + roomHex + "/p2wlan-room.log",
				Content: "room log file\n",
			},
		},
	}

	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var body bytes.Buffer
	writer := gzip.NewWriter(&body)
	if _, err := writer.Write(encoded); err != nil {
		t.Fatalf("gzip.Write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("gzip.Close: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/support/logs", &body)
	req.Header.Set("Content-Encoding", "gzip")
	req = req.WithContext(context.WithValue(req.Context(), auth.UserClaimsKey, &auth.Claims{
		UserID: "user-v2",
	}))
	recorder := httptest.NewRecorder()
	server.UploadSupportLogs(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("UploadSupportLogs v2: HTTP %d %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Success   bool   `json:"success"`
		UploadID  string `json:"upload_id"`
		Instances int    `json:"instances"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !response.Success || response.Instances != 2 {
		t.Fatalf("unexpected v2 response: %+v", response)
	}
}

func TestUploadSupportLogsV2WithInstancesOnly(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("LOG_UPLOAD_DIR", directory)
	server := NewServer(nil, nil, nil)
	roomHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	bundle := supportLogBundle{
		SchemaVersion: supportLogSchemaVersion2,
		UploadedAt:    "2026-09-09T08:00:00Z",
		DeviceName:    "linux-cli",
		Platform:      "linux-cli",
		Manifest: &supportLogManifest{
			TotalInstances:        2,
			HasRoomLogs:           true,
			RetainedRoomInstances: 1,
		},
		Instances: []supportLogInstance{
			{InstanceType: "main", NetworkID: "default", Log: "main\n"},
			{InstanceType: "room", NetworkID: "room-1", ProfileID: roomHex, Log: "room\n"},
		},
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	zw := gzip.NewWriter(&body)
	if _, err := zw.Write(encoded); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/support/logs", &body)
	req.Header.Set("Content-Encoding", "gzip")
	req = req.WithContext(context.WithValue(req.Context(), auth.UserClaimsKey, &auth.Claims{UserID: "cli-user"}))
	recorder := httptest.NewRecorder()
	server.UploadSupportLogs(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("instances-only bundle: HTTP %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestUploadSupportLogsRejectsInvalidFileNameOrTraversal(t *testing.T) {
	server := NewServer(nil, nil, nil)
	tests := []struct {
		name          string
		schemaVersion int
		fileName      string
	}{
		{"traversal in v1", supportLogSchemaVersion1, "../../etc/passwd"},
		{"room file in v1", supportLogSchemaVersion1, "p2wlan-room.log"},
		{"traversal in v2", supportLogSchemaVersion2, "rooms/../../p2wlan-room.log"},
		{"invalid profile_id in v2", supportLogSchemaVersion2, "rooms/short/p2wlan-room.log"},
		{"arbitrary file in v2", supportLogSchemaVersion2, "arbitrary.log"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bundle := supportLogBundle{
				SchemaVersion: tc.schemaVersion,
				UploadedAt:    "2026-09-09T08:00:00Z",
				DeviceName:    "Device",
				Platform:      "macos",
				Files: []supportLogBundleFile{{
					Name:    tc.fileName,
					Content: "content\n",
				}},
			}
			encoded, _ := json.Marshal(bundle)
			var body bytes.Buffer
			writer := gzip.NewWriter(&body)
			_, _ = writer.Write(encoded)
			_ = writer.Close()

			req := httptest.NewRequest(http.MethodPost, "/api/v1/support/logs", &body)
			req.Header.Set("Content-Encoding", "gzip")
			req = req.WithContext(context.WithValue(req.Context(), auth.UserClaimsKey, &auth.Claims{
				UserID: "user-1",
			}))
			recorder := httptest.NewRecorder()
			server.UploadSupportLogs(recorder, req)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("expected Bad Request for %s, got HTTP %d", tc.name, recorder.Code)
			}
		})
	}
}

func TestUploadSupportLogsRejectsDeviceCredentials(t *testing.T) {
	server := NewServer(nil, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/support/logs", bytes.NewReader(nil))
	req.Header.Set("Content-Encoding", "gzip")
	req = req.WithContext(context.WithValue(req.Context(), auth.DeviceClaimsKey, &auth.DeviceClaims{
		UserID: "user-1",
	}))
	recorder := httptest.NewRecorder()
	server.UploadSupportLogs(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("device credential accepted: HTTP %d", recorder.Code)
	}
}

func TestUploadSupportLogsV2CountsEachRoomOnce(t *testing.T) {
	t.Setenv("LOG_UPLOAD_DIR", t.TempDir())
	server := NewServer(nil, nil, nil)
	roomHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	bundle := supportLogBundle{
		SchemaVersion: 2, DeviceName: "review", Platform: "macos",
		Manifest: &supportLogManifest{TotalInstances: 2, HasRoomLogs: true},
		Files: []supportLogBundleFile{
			{Name: "p2wlan-daemon.log", Content: "main"},
			{Name: "rooms/" + roomHex + "/p2wlan-daemon.log", Content: "room"},
			{Name: "rooms/" + roomHex + "/status-summary.json", Content: "{}"},
		},
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	zw := gzip.NewWriter(&body)
	if _, err := zw.Write(encoded); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/support/logs", &body)
	req.Header.Set("Content-Encoding", "gzip")
	req = req.WithContext(context.WithValue(req.Context(), auth.UserClaimsKey, &auth.Claims{UserID: "review"}))
	rec := httptest.NewRecorder()
	server.UploadSupportLogs(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
	}
	var response struct {
		Instances int `json:"instances"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Instances != 2 {
		t.Fatalf("one main daemon and one room must be 2 instances, got %d", response.Instances)
	}
}

func TestUploadSupportLogsRejectsManifestTotalInstancesMismatch(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("LOG_UPLOAD_DIR", directory)
	server := NewServer(nil, nil, nil)
	roomHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	bundle := supportLogBundle{
		SchemaVersion: 2, DeviceName: "review", Platform: "macos",
		Manifest: &supportLogManifest{TotalInstances: 5, HasRoomLogs: true},
		Files: []supportLogBundleFile{
			{Name: "p2wlan-daemon.log", Content: "main"},
			{Name: "rooms/" + roomHex + "/p2wlan-daemon.log", Content: "room"},
		},
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	zw := gzip.NewWriter(&body)
	if _, err := zw.Write(encoded); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/support/logs", &body)
	req.Header.Set("Content-Encoding", "gzip")
	req = req.WithContext(context.WithValue(req.Context(), auth.UserClaimsKey, &auth.Claims{UserID: "review"}))
	rec := httptest.NewRecorder()
	server.UploadSupportLogs(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected HTTP 400 for manifest mismatch, got HTTP %d: %s", rec.Code, rec.Body.String())
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("rejected bundle was persisted: %+v", entries)
	}
}

func TestUploadSupportLogsV2AcceptsFiveAndEightRoomBundles(t *testing.T) {
	for _, roomCount := range []int{5, 8} {
		t.Run(fmt.Sprintf("%d rooms", roomCount), func(t *testing.T) {
			directory := t.TempDir()
			t.Setenv("LOG_UPLOAD_DIR", directory)
			server := NewServer(nil, nil, nil)
			bundle := supportLogBundleForRooms(roomCount)
			recorder := postSupportLogBundle(t, server, bundle)
			if recorder.Code != http.StatusOK {
				t.Fatalf("%d room bundle (%d files): HTTP %d %s", roomCount, len(bundle.Files), recorder.Code, recorder.Body.String())
			}
			var response struct {
				Success   bool `json:"success"`
				Instances int  `json:"instances"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if !response.Success || response.Instances != roomCount+1 {
				t.Fatalf("unexpected response: %+v", response)
			}
		})
	}
}

func TestUploadSupportLogsV2RejectsMoreThanDefaultRoomBudget(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("LOG_UPLOAD_DIR", directory)
	server := NewServer(nil, nil, nil)
	recorder := postSupportLogBundle(t, server, supportLogBundleForRooms(9))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 9 room bundle to be rejected, got HTTP %d: %s", recorder.Code, recorder.Body.String())
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("rejected bundle was persisted: %+v", entries)
	}
}

func TestUploadSupportLogsV2RejectsMultipleLogsForOneRoom(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("LOG_UPLOAD_DIR", directory)
	server := NewServer(nil, nil, nil)
	profileID := fmt.Sprintf("%064x", 1)
	bundle := supportLogBundle{
		SchemaVersion: supportLogSchemaVersion2,
		DeviceName:    "support-test",
		Platform:      "macos",
		Manifest: &supportLogManifest{
			TotalInstances: 2,
			HasRoomLogs:    true,
		},
		Files: []supportLogBundleFile{
			{Name: "p2wlan-daemon.log", Content: "main daemon log\n"},
			{Name: "rooms/" + profileID + "/p2wlan-daemon.log", Content: "new room log\n"},
			{Name: "rooms/" + profileID + "/p2wlan-room.log", Content: "legacy room log\n"},
		},
	}
	recorder := postSupportLogBundle(t, server, bundle)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected duplicate room logs to be rejected, got HTTP %d: %s", recorder.Code, recorder.Body.String())
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("rejected bundle was persisted: %+v", entries)
	}
}

func TestUploadSupportLogsV2RecordsOmittedRoomInstances(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("LOG_UPLOAD_DIR", directory)
	server := NewServer(nil, nil, nil)
	bundle := supportLogBundleForRooms(maxSupportLogRoomInstances)
	bundle.Manifest.OmittedRoomInstances = 1
	bundle.Manifest.OmittedReason = "room_instance_budget"
	recorder := postSupportLogBundle(t, server, bundle)
	if recorder.Code != http.StatusOK {
		t.Fatalf("omitted-room bundle: HTTP %d %s", recorder.Code, recorder.Body.String())
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected one stored bundle, got %+v", entries)
	}
	storedFile, err := os.Open(filepath.Join(directory, entries[0].Name()))
	if err != nil {
		t.Fatalf("Open upload: %v", err)
	}
	decompressed, err := gzip.NewReader(storedFile)
	if err != nil {
		t.Fatalf("stored gzip: %v", err)
	}
	storedBytes, err := io.ReadAll(decompressed)
	if err != nil {
		t.Fatalf("Read stored bundle: %v", err)
	}
	_ = decompressed.Close()
	_ = storedFile.Close()
	var stored storedSupportLogBundle
	if err := json.Unmarshal(storedBytes, &stored); err != nil {
		t.Fatalf("decode stored bundle: %v", err)
	}
	if stored.Bundle.Manifest == nil ||
		stored.Bundle.Manifest.OmittedRoomInstances != 1 ||
		stored.Bundle.Manifest.OmittedReason != "room_instance_budget" {
		t.Fatalf("omitted-room metadata was not preserved: %+v", stored.Bundle.Manifest)
	}
}

func supportLogBundleForRooms(roomCount int) supportLogBundle {
	files := []supportLogBundleFile{
		{Name: "p2wlan-daemon.log", Content: "main daemon log\n"},
		{Name: "p2wlan-client.log", Content: "client log\n"},
	}
	for room := 1; room <= roomCount; room++ {
		profileID := fmt.Sprintf("%064x", room)
		files = append(files,
			supportLogBundleFile{
				Name:    "rooms/" + profileID + "/p2wlan-daemon.log",
				Content: "room daemon log\n",
			},
			supportLogBundleFile{
				Name:    "rooms/" + profileID + "/status-summary.json",
				Content: `{"phase":"unavailable"}`,
			},
		)
	}
	return supportLogBundle{
		SchemaVersion: supportLogSchemaVersion2,
		DeviceName:    "support-test",
		Platform:      "macos",
		Manifest: &supportLogManifest{
			TotalInstances:        roomCount + 1,
			HasRoomLogs:           true,
			RetainedRoomInstances: roomCount,
		},
		Files: files,
	}
}

func postSupportLogBundle(t *testing.T, server *Server, bundle supportLogBundle) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var body bytes.Buffer
	writer := gzip.NewWriter(&body)
	if _, err := writer.Write(encoded); err != nil {
		t.Fatalf("gzip.Write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("gzip.Close: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/support/logs", &body)
	req.Header.Set("Content-Encoding", "gzip")
	req = req.WithContext(context.WithValue(req.Context(), auth.UserClaimsKey, &auth.Claims{
		UserID: "support-test",
	}))
	recorder := httptest.NewRecorder()
	server.UploadSupportLogs(recorder, req)
	return recorder
}

func TestSupportLogDirectoryResolutionPreservesOverridesAndDevelopmentDefault(t *testing.T) {
	absoluteDirectory := t.TempDir()
	absoluteDatabase := filepath.Join(absoluteDirectory, "state", "control.db")
	siblingUploads := filepath.Join(absoluteDirectory, "state", "log-uploads")
	explicitUploads := filepath.Join(absoluteDirectory, "custom-uploads")
	relativeUploads := filepath.Join("custom", "logs")
	legacyUploads := filepath.Join("data", "log-uploads")
	for _, tc := range []struct {
		name, uploadDirectory, databasePath, want string
	}{
		{"absolute override", explicitUploads, absoluteDatabase, explicitUploads},
		{"relative override", "  " + relativeUploads + "  ", absoluteDatabase, relativeUploads},
		{"absolute database", "", absoluteDatabase, siblingUploads},
		{"trimmed absolute database", " \t ", "  " + absoluteDatabase + "  ", siblingUploads},
		{"missing database", "", "", legacyUploads},
		{"blank database", "", " \t ", legacyUploads},
		{"relative database", "", filepath.Join("state", "control.db"), legacyUploads},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("LOG_UPLOAD_DIR", tc.uploadDirectory)
			t.Setenv("DB_PATH", tc.databasePath)
			if got := supportLogDirFromEnv(); got != tc.want {
				t.Fatalf("support log directory = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestUploadSupportLogsUnavailableDirectoryReportsOnlySafeFailure(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "private-storage-path-marker")
	if err := os.WriteFile(parent, []byte("existing-file"), 0o600); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(parent, "uploads")
	t.Setenv("LOG_UPLOAD_DIR", directory)
	server := NewServer(nil, nil, nil)
	bundle := supportLogBundleForRooms(0)
	bundle.DeviceName = "private-device-marker"
	bundle.ClientBuild = map[string]string{"token": "private-token-marker"}
	bundle.Files[0].Content = "private-bundle-content-marker"
	var journal bytes.Buffer
	previousOutput := log.Writer()
	log.SetOutput(&journal)
	t.Cleanup(func() { log.SetOutput(previousOutput) })

	recorder := postSupportLogBundle(t, server, bundle)
	if recorder.Code != http.StatusInternalServerError || recorder.Body.String() != "{\"error\":\"support log storage failed\"}\n" {
		t.Fatalf("expected unchanged generic storage error, got HTTP %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(journal.String(), "event=support_log_storage_failed stage=create_directory reason=") {
		t.Fatalf("missing safe storage diagnostic: %s", journal.String())
	}
	for _, secret := range []string{directory, parent, "private-storage-path-marker", "private-device-marker", "private-token-marker", "private-bundle-content-marker", "support-test"} {
		if strings.Contains(recorder.Body.String(), secret) || strings.Contains(journal.String(), secret) {
			t.Fatalf("storage failure leaked fixture metadata %q", secret)
		}
	}
	content, err := os.ReadFile(parent)
	if err != nil || string(content) != "existing-file" {
		t.Fatalf("unavailable directory modified existing data: %q, %v", content, err)
	}
}

func TestSupportLogStorageFailurePreservesCauseWithoutFormattingIt(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cause  error
		reason string
	}{
		{"permission", os.ErrPermission, "permission_denied"},
		{"missing", os.ErrNotExist, "path_missing"},
		{"exists", os.ErrExist, "already_exists"},
		{"not directory", syscall.ENOTDIR, "not_directory"},
		{"no space", syscall.ENOSPC, "no_space"},
		{"read only", syscall.EROFS, "read_only_filesystem"},
		{"invalid", os.ErrInvalid, "invalid_argument"},
		{"unknown", errors.New("private-inner-error-marker"), "io_error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			underlying := &os.PathError{Op: "private-operation-marker", Path: "private-path-marker", Err: tc.cause}
			err := &supportLogStorageError{stage: supportLogPublishBundle, cause: underlying}
			if !errors.Is(err, tc.cause) {
				t.Fatal("wrapped storage error lost its cause")
			}
			var pathError *os.PathError
			if !errors.As(err, &pathError) || pathError != underlying {
				t.Fatal("wrapped storage error lost the original typed error")
			}
			stage, reason := supportLogStorageFailureDetails(fmt.Errorf("private-wrapper-marker: %w", err))
			if stage != "publish_bundle" || reason != tc.reason {
				t.Fatalf("unexpected safe classification: %s/%s", stage, reason)
			}
			if got, want := err.Error(), "support log storage failed: stage=publish_bundle reason="+tc.reason; got != want {
				t.Fatalf("unsafe or unstable error formatting: %q", got)
			}
		})
	}
	stage, reason := supportLogStorageFailureDetails(&supportLogStorageError{
		stage: supportLogStorageStage("private-stage-marker"), cause: errors.New("private-error-marker"),
	})
	if stage != "unknown" || reason != "io_error" {
		t.Fatalf("unknown fields must not be echoed: %s/%s", stage, reason)
	}
}

func TestPersistSupportLogBundleRejectsEmptyOrUnavailableDirectory(t *testing.T) {
	if err := persistSupportLogBundle(" ", "upload", storedSupportLogBundle{}); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("empty directory must preserve invalid-argument cause, got %v", err)
	}
	parent := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(parent, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := persistSupportLogBundle(filepath.Join(parent, "uploads"), "upload", storedSupportLogBundle{})
	var storageErr *supportLogStorageError
	var pathErr *os.PathError
	if !errors.As(err, &storageErr) || storageErr.stage != supportLogCreateDirectory || !errors.As(err, &pathErr) || !errors.Is(err, pathErr.Err) {
		t.Fatalf("directory failure must retain stage and filesystem cause, got %v", err)
	}
}

func TestPersistSupportLogBundleStopsWhenDirectoryChmodFails(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "uploads")
	cause := &os.PathError{Op: "chmod", Path: directory, Err: os.ErrPermission}
	chmodCalls := 0
	err := persistSupportLogBundleWithDirectoryMode(directory, "upload", storedSupportLogBundle{}, func(path string, mode os.FileMode) error {
		chmodCalls++
		if path != directory || mode != 0o700 {
			t.Fatalf("unexpected directory permission operation: %q, %v", path, mode)
		}
		return cause
	})
	stage, reason := supportLogStorageFailureDetails(err)
	if chmodCalls != 1 || stage != "restrict_directory" || reason != "permission_denied" || !errors.Is(err, cause) {
		t.Fatalf("chmod failure was swallowed or misclassified: calls=%d, error=%v", chmodCalls, err)
	}
	entries, readErr := os.ReadDir(directory)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("chmod failure must stop before creating artifacts: %v, %v", entries, readErr)
	}
}

func TestPersistSupportLogBundlePublishFailureCleansPrivateTemporaryFile(t *testing.T) {
	directory := t.TempDir()
	bundle := storedSupportLogBundle{ReceivedAt: "2026-09-28T12:00:00Z", UserID: "private-user-marker"}
	finalName := "2026-09-28-upload.json.gz"
	if err := os.Mkdir(filepath.Join(directory, finalName), 0o700); err != nil {
		t.Fatal(err)
	}
	err := persistSupportLogBundle(directory, "upload", bundle)
	var storageErr *supportLogStorageError
	if !errors.As(err, &storageErr) || storageErr.stage != supportLogPublishBundle {
		t.Fatalf("expected publish-stage error, got %v", err)
	}
	entries, readErr := os.ReadDir(directory)
	if readErr != nil || len(entries) != 1 || entries[0].Name() != finalName || !entries[0].IsDir() {
		t.Fatalf("failed publication must preserve target and remove temporary file: %v, %v", entries, readErr)
	}
}
