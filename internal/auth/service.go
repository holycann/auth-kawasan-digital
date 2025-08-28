package auth

import (
	"context"

	"github.com/holycann/auth-kawasan-digital/pkg/errors"
	"github.com/holycann/auth-kawasan-digital/pkg/logger"
	"github.com/holycann/auth-kawasan-digital/pkg/validator"
	"github.com/supabase-community/auth-go/types"
)

// AuthService defines the business logic for authentication operations
type AuthService struct {
	repo   AuthRepository
	logger *logger.Logger
}

// NewAuthService creates a new authentication service
func NewAuthService(repo AuthRepository, log *logger.Logger) *AuthService {
	return &AuthService{
		repo:   repo,
		logger: log,
	}
}

// Register handles user registration with comprehensive validation
func (s *AuthService) Register(ctx context.Context, req AuthRegister) (*AuthResponse, error) {
	// Validate registration request
	if err := validator.ValidateStruct(req); err != nil {
		s.logger.Error("Registration validation failed", "error", err)
		return nil, errors.New(
			errors.ErrValidation,
			"Invalid registration details",
			err,
			errors.WithContext("validation_errors", err.Error()),
		)
	}

	// Attempt user registration
	supabaseResp, err := s.repo.SignUp(ctx, req)
	if err != nil {
		s.logger.Error("User registration failed", "email", req.Email, "error", err)
		return nil, errors.Wrap(
			err,
			errors.ErrAuthentication,
			"Registration failed",
			errors.WithContext("email", req.Email),
		)
	}

	s.logger.Info("User registered successfully", "email", req.Email)
	return supabaseResp, nil
}

// Login handles user authentication
func (s *AuthService) Login(ctx context.Context, req Credentials) (*AuthResponse, error) {
	// Validate login request
	if err := validator.ValidateStruct(req); err != nil {
		s.logger.Error("Login validation failed", "error", err)
		return nil, errors.New(
			errors.ErrValidation,
			"Invalid login details",
			err,
			errors.WithContext("validation_errors", err.Error()),
		)
	}

	// Attempt user login
	supabaseResp, err := s.repo.SignInWithPassword(ctx, req)
	if err != nil {
		s.logger.Error("User login failed", "email", req.Email, "error", err)
		return nil, errors.Wrap(
			err,
			errors.ErrAuthentication,
			"Login failed",
			errors.WithContext("email", req.Email),
		)
	}

	s.logger.Info("User logged in successfully", "email", req.Email)
	return supabaseResp, nil
}

// ResetPassword initiates password reset process
func (s *AuthService) ResetPassword(ctx context.Context, email string) error {
	// Validate email
	if err := validator.ValidateString(email, "Email", 1, 255); err != nil {
		s.logger.Error("Password reset validation failed", "error", err)
		return errors.New(
			errors.ErrValidation,
			"Invalid email for password reset",
			err,
			errors.WithContext("email", email),
		)
	}

	// Initiate password reset
	req := PasswordResetRequest{Email: email}
	err := s.repo.ResetPassword(ctx, req)
	if err != nil {
		s.logger.Error("Password reset request failed", "email", email, "error", err)
		return errors.Wrap(
			err,
			errors.ErrAuthentication,
			"Password reset request failed",
			errors.WithContext("email", email),
		)
	}

	s.logger.Info("Password reset initiated", "email", email)
	return nil
}

// MultiFactorSetup handles MFA enrollment
func (s *AuthService) MultiFactorSetup(ctx context.Context, req types.EnrollFactorRequest) (*types.EnrollFactorResponse, error) {
	// Validate MFA enrollment request
	if req.FactorType == "" {
		return nil, errors.New(
			errors.ErrValidation,
			"Invalid MFA factor type",
			nil,
			errors.WithContext("factor_type", "empty"),
		)
	}

	// Attempt MFA factor enrollment
	resp, err := s.repo.EnrollFactor(ctx, req)
	if err != nil {
		s.logger.Error("MFA enrollment failed", "factor_type", req.FactorType, "error", err)
		return nil, errors.Wrap(
			err,
			errors.ErrAuthentication,
			"MFA enrollment failed",
			errors.WithContext("factor_type", req.FactorType),
		)
	}

	s.logger.Info("MFA factor enrolled successfully", "factor_type", req.FactorType)
	return resp, nil
}

// Logout handles user session termination
func (s *AuthService) Logout(ctx context.Context) error {
	err := s.repo.Logout(ctx)
	if err != nil {
		s.logger.Error("Logout failed", "error", err)
		return errors.Wrap(
			err,
			errors.ErrAuthentication,
			"Logout failed",
		)
	}

	s.logger.Info("User logged out successfully")
	return nil
}

// RefreshToken handles token renewal
func (s *AuthService) RefreshToken(ctx context.Context, refreshToken string) (*AuthResponse, error) {
	if refreshToken == "" {
		return nil, errors.New(
			errors.ErrValidation,
			"Invalid refresh token",
			nil,
			errors.WithContext("refresh_token", "empty"),
		)
	}

	resp, err := s.repo.RefreshToken(ctx, refreshToken)
	if err != nil {
		s.logger.Error("Token refresh failed", "error", err)
		return nil, errors.Wrap(
			err,
			errors.ErrAuthentication,
			"Token refresh failed",
		)
	}

	s.logger.Info("Token refreshed successfully")
	return resp, nil
}
