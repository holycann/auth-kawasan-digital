package auth

import (
	"github.com/supabase-community/auth-go/types"
)

// Credentials represents basic authentication credentials
type Credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// AuthRegister represents registration-specific details
type AuthRegister struct {
	Credentials
	Username    string `json:"username,omitempty"`
	FullName    string `json:"full_name,omitempty"`
	Address     string `json:"address,omitempty"`
	Birthday    string `json:"birthday,omitempty"`
	PhoneNumber string `json:"phone_number,omitempty"`
	Role        string `json:"role,omitempty"`
}

// AuthResponse represents the authentication response
type AuthResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresAt    int64  `json:"expires_at"`
}

// MultiFactorRequest represents MFA/OTP authentication details
type MultiFactorRequest struct {
	FactorType   types.FactorType `json:"factor_type"`
	FriendlyName string           `json:"friendly_name"`
	Issuer       string           `json:"issuer,omitempty"`
	Code         string           `json:"code,omitempty"`
}

// PasswordResetRequest represents password reset details
type PasswordResetRequest struct {
	Email       string `json:"email"`
	NewPassword string `json:"new_password"`
}
