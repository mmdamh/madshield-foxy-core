package service

// MadShield hook (see native/fxvpn/patches): RememberPassword false keeps the Firefox Account password out of the data
// folder. It is used for the sign-in only and then forgotten; an account whose tokens Mozilla revokes asks for a new
// sign-in instead of signing in again by itself.
var RememberPassword = true
