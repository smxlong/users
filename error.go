package users

// Error type for users package.
type Error string

// Error returns the error message.
func (e Error) Error() string {
	return string(e)
}

// Error values for users package.
const (
	ErrPasswordHashUnknownAlgorithm Error = "unknown algorithm"
	ErrPasswordHashMismatch         Error = "mismatched hash and password"
	ErrEmailAddressInvalid          Error = "invalid email address"
	ErrTokenSecretRequired          Error = "token secret required"
	ErrTokenInvalid                 Error = "invalid token"
)
