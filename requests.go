package main

// RegisterRequest is for registration requests
type RegisterRequest struct {
	Username string `json:"username"`
	Nickname string `json:"nickname"`
	Password string `json:"password"`
}

// LoginRequest is for login requests
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
