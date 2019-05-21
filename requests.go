package main

// RegisterRequest is for registration requests
type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

// LoginRequest is for login requests
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
