package auth

type RegisterRequest struct {
	Email    string
	Password string
	Username string
}

type RegisterResponse struct {
	UserID string
}

type LoginRequest struct {
	Email    string
	Password string
}

type LoginResponse struct {
	AccessToken  string
	RefreshToken string
	UserID       string
	Roles        []string
}

type RefreshTokenRequest struct {
	RefreshToken string
}

type RefreshTokenResponse struct {
	AccessToken  string
	RefreshToken string
	UserID       string
	Roles        []string
}

type ValidateTokenRequest struct {
	Token string
}

type ValidateTokenResponse struct {
	UserID string
	Roles  []string
	Valid  bool
}
