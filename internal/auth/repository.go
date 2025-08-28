package auth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/holycann/auth-kawasan-digital/pkg/logger"
	"github.com/holycann/auth-kawasan-digital/pkg/supabase"
	"github.com/supabase-community/auth-go/types"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
	ErrAuthFailed         = errors.New("authentication failed")
)

// AuthRepository defines the interface for authentication operations
type AuthRepository interface {
	// User Authentication
	SignUp(ctx context.Context, req AuthRegister) (*AuthResponse, error)
	SignInWithPassword(ctx context.Context, req Credentials) (*AuthResponse, error)
	SignInWithOTP(ctx context.Context, req MultiFactorRequest) error
	Logout(ctx context.Context) error
	RefreshToken(ctx context.Context, refreshToken string) (*AuthResponse, error)

	// Password Management
	ResetPassword(ctx context.Context, req PasswordResetRequest) error
	VerifyPasswordReset(ctx context.Context, req types.VerifyRequest) (*types.VerifyResponse, error)

	// Multi-Factor Authentication
	EnrollFactor(ctx context.Context, req types.EnrollFactorRequest) (*types.EnrollFactorResponse, error)
	ChallengeFactor(ctx context.Context, req types.ChallengeFactorRequest) (*types.ChallengeFactorResponse, error)
	VerifyFactor(ctx context.Context, req types.VerifyFactorRequest) (*types.VerifyFactorResponse, error)
	UnenrollFactor(ctx context.Context, factorID uuid.UUID) (*types.UnenrollFactorResponse, error)

	// External Provider Authentication
	SignInWithProvider(ctx context.Context, provider types.Provider, redirectTo string) (*types.AuthorizeResponse, error)

	// System Information
	GetAuthSettings(ctx context.Context) (*types.SettingsResponse, error)
}

// SupabaseAuthRepository implements AuthRepository using Supabase auth
type SupabaseAuthRepository struct {
	client *supabase.SupabaseAuth
	logger *logger.Logger
}

// NewSupabaseAuthRepository creates a new Supabase authentication repository
func NewSupabaseAuthRepository(client *supabase.SupabaseAuth, log *logger.Logger) *SupabaseAuthRepository {
	return &SupabaseAuthRepository{
		client: client,
		logger: log,
	}
}

// SignUp registers a new user
func (r *SupabaseAuthRepository) SignUp(ctx context.Context, req AuthRegister) (*AuthResponse, error) {
	r.logger.Info("Attempting user signup", "email", req.Email)

	signupReq := types.SignupRequest{
		Email:    req.Email,
		Password: req.Password,
	}

	resp, err := r.client.GetClient().Signup(signupReq)
	if err != nil {
		r.logger.Error("Signup failed", "error", err)
		return nil, ErrAuthFailed
	}

	// Convert Supabase response to local authentication response
	authResp := &AuthResponse{
		AccessToken:  resp.Session.AccessToken,
		RefreshToken: resp.Session.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Second * time.Duration(resp.Session.ExpiresIn)).Unix(),
	}

	return authResp, nil
}

// SignInWithPassword authenticates a user with email and password
func (r *SupabaseAuthRepository) SignInWithPassword(ctx context.Context, req Credentials) (*AuthResponse, error) {
	r.logger.Info("Attempting user login", "email", req.Email)

	resp, err := r.client.GetClient().SignInWithEmailPassword(req.Email, req.Password)
	if err != nil {
		r.logger.Error("Login failed", "error", err)
		return nil, ErrInvalidCredentials
	}

	// Convert Supabase token response to local authentication response
	authResp := &AuthResponse{
		AccessToken:  resp.Session.AccessToken,
		RefreshToken: resp.Session.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Second * time.Duration(resp.Session.ExpiresIn)).Unix(),
	}

	return authResp, nil
}

// SignInWithOTP sends a one-time password
func (r *SupabaseAuthRepository) SignInWithOTP(ctx context.Context, req MultiFactorRequest) error {
	r.logger.Info("Sending OTP", "email", req.FriendlyName)

	otpReq := types.OTPRequest{
		Email: req.FriendlyName,
	}

	err := r.client.GetClient().OTP(otpReq)
	if err != nil {
		r.logger.Error("OTP sending failed", "error", err)
		return ErrAuthFailed
	}

	return nil
}

// Logout terminates the current user session
func (r *SupabaseAuthRepository) Logout(ctx context.Context) error {
	r.logger.Info("Attempting user logout")

	err := r.client.GetClient().Logout()
	if err != nil {
		r.logger.Error("Logout failed", "error", err)
		return ErrAuthFailed
	}

	return nil
}

// RefreshToken handles token renewal
func (r *SupabaseAuthRepository) RefreshToken(ctx context.Context, refreshToken string) (*AuthResponse, error) {
	r.logger.Info("Refreshing authentication token")

	resp, err := r.client.GetClient().RefreshToken(refreshToken)
	if err != nil {
		r.logger.Error("Token refresh failed", "error", err)
		return nil, ErrAuthFailed
	}

	// Convert Supabase token response to local authentication response
	authResp := &AuthResponse{
		AccessToken:  resp.Session.AccessToken,
		RefreshToken: resp.Session.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Second * time.Duration(resp.Session.ExpiresIn)).Unix(),
	}

	return authResp, nil
}

// ResetPassword initiates the password reset process
func (r *SupabaseAuthRepository) ResetPassword(ctx context.Context, req PasswordResetRequest) error {
	r.logger.Info("Initiating password reset", "email", req.Email)

	recoverReq := types.RecoverRequest{
		Email: req.Email,
	}

	err := r.client.GetClient().Recover(recoverReq)
	if err != nil {
		r.logger.Error("Password reset failed", "error", err)
		return ErrAuthFailed
	}

	return nil
}

// VerifyPasswordReset completes the password reset process
func (r *SupabaseAuthRepository) VerifyPasswordReset(ctx context.Context, req types.VerifyRequest) (*types.VerifyResponse, error) {
	r.logger.Info("Verifying password reset")

	resp, err := r.client.GetClient().Verify(req)
	if err != nil {
		r.logger.Error("Password reset verification failed", "error", err)
		return nil, ErrAuthFailed
	}

	return resp, nil
}

// EnrollFactor sets up multi-factor authentication
func (r *SupabaseAuthRepository) EnrollFactor(ctx context.Context, req types.EnrollFactorRequest) (*types.EnrollFactorResponse, error) {
	r.logger.Info("Enrolling authentication factor", "type", req.FactorType)

	resp, err := r.client.GetClient().EnrollFactor(req)
	if err != nil {
		r.logger.Error("Factor enrollment failed", "error", err)
		return nil, ErrAuthFailed
	}

	return resp, nil
}

// ChallengeFactor initiates a multi-factor authentication challenge
func (r *SupabaseAuthRepository) ChallengeFactor(ctx context.Context, req types.ChallengeFactorRequest) (*types.ChallengeFactorResponse, error) {
	r.logger.Info("Challenging authentication factor", "factorID", req.FactorID)

	resp, err := r.client.GetClient().ChallengeFactor(req)
	if err != nil {
		r.logger.Error("Factor challenge failed", "error", err)
		return nil, ErrAuthFailed
	}

	return resp, nil
}

// VerifyFactor completes a multi-factor authentication challenge
func (r *SupabaseAuthRepository) VerifyFactor(ctx context.Context, req types.VerifyFactorRequest) (*types.VerifyFactorResponse, error) {
	r.logger.Info("Verifying authentication factor")

	resp, err := r.client.GetClient().VerifyFactor(req)
	if err != nil {
		r.logger.Error("Factor verification failed", "error", err)
		return nil, ErrAuthFailed
	}

	return resp, nil
}

// UnenrollFactor removes a multi-factor authentication method
func (r *SupabaseAuthRepository) UnenrollFactor(ctx context.Context, factorID uuid.UUID) (*types.UnenrollFactorResponse, error) {
	r.logger.Info("Unenrolling authentication factor", "factorID", factorID)

	req := types.UnenrollFactorRequest{
		FactorID: factorID,
	}

	resp, err := r.client.GetClient().UnenrollFactor(req)
	if err != nil {
		r.logger.Error("Factor unenrollment failed", "error", err)
		return nil, ErrAuthFailed
	}

	return resp, nil
}

// SignInWithProvider initiates authentication with an external provider
func (r *SupabaseAuthRepository) SignInWithProvider(ctx context.Context, provider types.Provider, redirectTo string) (*types.AuthorizeResponse, error) {
	r.logger.Info("Initiating authentication with provider", "provider", provider)

	req := types.AuthorizeRequest{
		Provider:   provider,
		RedirectTo: redirectTo,
		FlowType:   types.FlowPKCE,
	}

	resp, err := r.client.GetClient().Authorize(req)
	if err != nil {
		r.logger.Error("Provider authentication failed", "error", err)
		return nil, ErrAuthFailed
	}

	return resp, nil
}

// GetAuthSettings retrieves the current authentication system settings
func (r *SupabaseAuthRepository) GetAuthSettings(ctx context.Context) (*types.SettingsResponse, error) {
	r.logger.Info("Fetching authentication settings")

	resp, err := r.client.GetClient().GetSettings()
	if err != nil {
		r.logger.Error("Fetching auth settings failed", "error", err)
		return nil, ErrAuthFailed
	}

	return resp, nil
}

// Ensure SupabaseAuthRepository implements AuthRepository interface
var _ AuthRepository = (*SupabaseAuthRepository)(nil)
