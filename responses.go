package main

// ErrResponse is used for returning errors to the client
type ErrResponse struct {
	Err string `json:"err"`
}

// LoginResponse used to signify successful login to the client
type LoginResponse struct {
	Jwt string `json:"jwt"`
}
