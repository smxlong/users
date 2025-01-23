package users

import (
	"context"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/smxlong/users/ent"
)

// TokenOptions control how we create and validate tokens.
type TokenOptions struct {
	// Issuer to use in the token. Optional. If not set, defaults to "users".
	Issuer string `json:"issuer"`
	// Audience to use in the token. Optional. If not set, defaults to "users".
	Audience string `json:"audience"`
	// Secret to use for signing the token. Required.
	Secret string
	// ValidFor is the duration the token is valid for. Optional. If not set,
	// defaults to 1 hour.
	ValidFor time.Duration
	// NotValidBefore is the time before which the token is invalid. Optional. If
	// not set, defaults to now.
	NotValidBefore time.Time
}

// GetIssuer returns the TokenOptions Issuer, or the default if not set.
func (o *TokenOptions) GetIssuer() string {
	if o.Issuer == "" {
		return "users"
	}
	return o.Issuer
}

// GetAudience returns the TokenOptions Audience, or the default if not set.
func (o *TokenOptions) GetAudience() string {
	if o.Audience == "" {
		return "users"
	}
	return o.Audience
}

// GetValidFor returns the TokenOptions ValidFor, or the default if not set.
func (o *TokenOptions) GetValidFor() time.Duration {
	if o.ValidFor == 0 {
		return time.Hour
	}
	return o.ValidFor
}

// GetNotValidBefore returns the TokenOptions NotValidBefore, or the default if not set.
func (o *TokenOptions) GetNotValidBefore(now time.Time) time.Time {
	return o.NotValidBefore
}

// NewToken creates a new JWT for a user.
func NewToken(u *ent.User, opts *TokenOptions) (string, error) {
	now := time.Now()
	if opts.Secret == "" {
		return "", ErrTokenSecretRequired
	}
	claims := jwt.New()
	claims.Set(jwt.SubjectKey, u.Email)
	claims.Set(jwt.IssuerKey, opts.GetIssuer())
	claims.Set(jwt.AudienceKey, opts.GetAudience())
	claims.Set(jwt.IssuedAtKey, now.Unix())
	claims.Set(jwt.ExpirationKey, now.Add(opts.GetValidFor()).Unix())
	nbf := opts.GetNotValidBefore(now)
	if !nbf.IsZero() {
		claims.Set(jwt.NotBeforeKey, nbf.Unix())
	}
	token, err := jwt.Sign(claims, jwt.WithKey(jwa.HS256(), []byte(opts.Secret)))
	if err != nil {
		return "", err
	}
	return string(token), nil
}

// ValidateToken validates a JWT for a user, returning the user.
func ValidateToken(ctx context.Context, client *ent.Client, token string, opts *TokenOptions) (*ent.User, error) {
	if opts.Secret == "" {
		return nil, ErrTokenSecretRequired
	}
	claims, err := jwt.Parse([]byte(token),
		jwt.WithIssuer(opts.GetIssuer()),
		jwt.WithAudience(opts.GetAudience()),
		jwt.WithKey(jwa.HS256(), []byte(opts.Secret)),
	)
	if err != nil {
		return nil, err
	}
	sub, _ := claims.Subject()
	u, err := FindByEmail(ctx, client, sub)
	if err != nil {
		return nil, err
	}
	return u, nil
}
