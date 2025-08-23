package supabase

import supabaseAuth "github.com/supabase-community/auth-go"

type SupabaseAuth struct {
	auth supabaseAuth.Client
}

type SupabaseAuthConfig struct {
	ApiKey    string
	ProjectID string
}

func NewSupabaseAuth(cfg SupabaseAuthConfig) *SupabaseAuth {
	client := supabaseAuth.New(
		cfg.ProjectID,
		cfg.ApiKey,
	)

	return &SupabaseAuth{
		auth: client,
	}
}

func (s *SupabaseAuth) GetClient() supabaseAuth.Client {
	return s.auth
}
