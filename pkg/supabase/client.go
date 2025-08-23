package supabase

import (
	"fmt"
	"sync"

	"github.com/supabase-community/supabase-go"
)

type SupabaseClientConfig struct {
	ProjectID string
	ApiSecret string
}

type SupabaseClient struct {
	mu     sync.RWMutex
	client *supabase.Client
}

func NewSupabaseClient(cfg SupabaseClientConfig) (*SupabaseClient, error) {
	if cfg.ApiSecret == "" || cfg.ProjectID == "" {
		return nil, fmt.Errorf("Supabase Api Key & Project ID Cannot Be Empty")
	}

	client, err := supabase.NewClient(fmt.Sprintf("https://%s.supabase.co", cfg.ProjectID), cfg.ApiSecret, &supabase.ClientOptions{})
	if err != nil {
		return nil, fmt.Errorf("Failed To Initialize Supabase Client: %v", err)
	}

	return &SupabaseClient{
		client: client,
	}, nil
}

func (s *SupabaseClient) GetClient() *supabase.Client {
	return s.client
}
