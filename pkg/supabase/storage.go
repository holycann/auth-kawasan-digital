package supabase

import (
	"context"
	"fmt"
	"mime/multipart"
	"path/filepath"
	"strings"

	storage_go "github.com/supabase-community/storage-go"
)

// StorageConfig provides comprehensive configuration for Supabase storage
type StorageConfig struct {
	// Supabase project details
	ProjectID    string
	JwtApiSecret string

	// Storage bucket configuration
	BucketID      string
	DefaultFolder string

	// Optional custom headers for client initialization
	Headers map[string]string

	// Advanced configuration options
	MaxFileSize         int64
	AllowedFileTypes    []string
	DefaultCacheControl string
}

// SupabaseStorage provides enhanced storage management capabilities
type SupabaseStorage struct {
	client *storage_go.Client
	config StorageConfig
}

// NewSupabaseStorage creates an enhanced Supabase storage client
func NewSupabaseStorage(cfg StorageConfig) *SupabaseStorage {
	// Use default headers if not provided
	if cfg.Headers == nil {
		cfg.Headers = make(map[string]string)
	}

	// Set default max file size if not specified
	if cfg.MaxFileSize == 0 {
		cfg.MaxFileSize = 10 * 1024 * 1024 // 10MB default
	}

	// Set default allowed file types if not specified
	if len(cfg.AllowedFileTypes) == 0 {
		cfg.AllowedFileTypes = []string{
			"image/jpeg", "image/png", "image/gif",
			"image/webp", "application/pdf",
		}
	}

	// Set default cache control if not specified
	if cfg.DefaultCacheControl == "" {
		cfg.DefaultCacheControl = "max-age=3600"
	}

	storageClient := storage_go.NewClient(
		fmt.Sprintf("https://%s.supabase.co/storage/v1", cfg.ProjectID),
		cfg.JwtApiSecret,
		cfg.Headers,
	)

	return &SupabaseStorage{
		client: storageClient,
		config: cfg,
	}
}

// Upload handles file upload with comprehensive validation and storage
func (s *SupabaseStorage) Upload(
	ctx context.Context,
	file *multipart.FileHeader,
	path string,
	opts ...storage_go.FileOptions,
) (string, error) {
	// Validate file size
	if file.Size > s.config.MaxFileSize {
		return "", fmt.Errorf("file size %d bytes exceeds maximum limit of %d",
			file.Size, s.config.MaxFileSize)
	}

	// Validate file type
	fileType := file.Header.Get("Content-Type")
	if !s.isAllowedFileType(fileType) {
		return "", fmt.Errorf("unsupported file type: %s", fileType)
	}

	// Open the file
	src, err := file.Open()
	if err != nil {
		return "", fmt.Errorf("failed to open uploaded file: %w", err)
	}
	defer src.Close()

	// Construct full path
	fullPath := filepath.ToSlash(filepath.Join(
		s.config.DefaultFolder,
		path,
	))

	// Prepare file options
	fileOpts := storage_go.FileOptions{
		Upsert:       boolPtr(true),
		CacheControl: stringPtr(s.config.DefaultCacheControl),
		ContentType:  stringPtr(fileType),
	}

	// Merge with any provided options
	if len(opts) > 0 {
		fileOpts = mergeFileOptions(fileOpts, opts[0])
	}

	// Upload file
	_, err = s.client.UploadFile(
		s.config.BucketID,
		fullPath,
		src,
		fileOpts,
	)
	if err != nil {
		return "", err
	}
	return fullPath, nil
}

// mergeFileOptions combines default and custom file options
func mergeFileOptions(defaultOpts, customOpts storage_go.FileOptions) storage_go.FileOptions {
	if customOpts.Upsert != nil {
		defaultOpts.Upsert = customOpts.Upsert
	}
	if customOpts.CacheControl != nil {
		defaultOpts.CacheControl = customOpts.CacheControl
	}
	if customOpts.ContentType != nil {
		defaultOpts.ContentType = customOpts.ContentType
	}
	return defaultOpts
}

// isAllowedFileType checks if the file type is in the allowed list
func (s *SupabaseStorage) isAllowedFileType(fileType string) bool {
	// If no allowed types specified, allow all
	if len(s.config.AllowedFileTypes) == 0 {
		return true
	}

	// Normalize file type
	fileType = strings.ToLower(strings.TrimSpace(fileType))

	// Check if file type matches any allowed type
	for _, allowedType := range s.config.AllowedFileTypes {
		if strings.ToLower(allowedType) == fileType {
			return true
		}
	}

	return false
}

// Delete removes a file from storage
func (s *SupabaseStorage) Delete(
	ctx context.Context,
	filepath string,
) (string, error) {
	_, err := s.client.RemoveFile(
		s.config.BucketID,
		[]string{filepath},
	)
	if err != nil {
		return "", err
	}

	// Return success message as a string
	return "File deleted successfully", nil
}

// ListFiles retrieves files in a specific path
func (s *SupabaseStorage) ListFiles(
	ctx context.Context,
	path string,
	opts ...storage_go.FileSearchOptions,
) ([]storage_go.FileObject, error) {
	searchOpts := storage_go.FileSearchOptions{}
	if len(opts) > 0 {
		searchOpts = opts[0]
	}

	return s.client.ListFiles(
		s.config.BucketID,
		path,
		searchOpts,
	)
}

// GetPublicURL generates a public URL for a file
func (s *SupabaseStorage) GetPublicURL(
	path string,
	transformOpts ...storage_go.UrlOptions,
) (string, error) {
	resp := s.client.GetPublicUrl(
		s.config.BucketID,
		filepath.ToSlash(filepath.Join(
			s.config.DefaultFolder,
			path,
		)),
		transformOpts...,
	)
	return resp.SignedURL, nil
}

// Helper functions to create pointers for optional values
func stringPtr(s string) *string {
	return &s
}

func boolPtr(b bool) *bool {
	return &b
}

func int64Ptr(i int64) *int64 {
	return &i
}
