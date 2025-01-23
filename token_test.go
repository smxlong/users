package users

import (
	"context"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/require"
)

func Test_that_NewToken_creates_a_user_token(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	u, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	tok, err := NewToken(u, &TokenOptions{Secret: "foo"})
	require.NoError(t, err)
	require.NotZero(t, tok)
}

func Test_that_NewToken_sets_the_audience_and_issuer(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	u, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	tok, err := NewToken(u, &TokenOptions{Secret: "foo"})
	require.NoError(t, err)
	ptok, err := jwt.Parse([]byte(tok), jwt.WithIssuer("users"), jwt.WithAudience("users"), jwt.WithKey(jwa.HS256(), []byte("foo")))
	require.NoError(t, err)
	require.NotNil(t, ptok)
	iss, ok := ptok.Issuer()
	require.True(t, ok)
	require.Equal(t, "users", iss)
	aud, ok := ptok.Audience()
	require.True(t, ok)
	require.Len(t, aud, 1)
	require.Equal(t, "users", aud[0])
}

func Test_that_NewToken_sets_the_expiration(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	u, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	validFor := 5 * time.Minute
	tok, err := NewToken(u, &TokenOptions{
		Secret:   "foo",
		ValidFor: validFor,
	})
	require.NoError(t, err)
	ptok, err := jwt.Parse([]byte(tok), jwt.WithIssuer("users"), jwt.WithAudience("users"), jwt.WithKey(jwa.HS256(), []byte("foo")))
	require.NoError(t, err)
	require.NotNil(t, ptok)
	exp, ok := ptok.Expiration()
	require.True(t, ok)
	const TIME_COMPARE_TOLERANCE = 1 * time.Second
	require.WithinDuration(t, time.Now().Add(validFor), exp, TIME_COMPARE_TOLERANCE)
}

func Test_that_NewToken_omits_nbf_if_not_set(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	u, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	tok, err := NewToken(u, &TokenOptions{Secret: "foo"})
	require.NoError(t, err)
	ptok, err := jwt.Parse([]byte(tok), jwt.WithIssuer("users"), jwt.WithAudience("users"), jwt.WithKey(jwa.HS256(), []byte("foo")))
	require.NoError(t, err)
	require.NotNil(t, ptok)
	_, ok := ptok.NotBefore()
	require.False(t, ok)
}

func Test_that_NewToken_includes_nbf_if_set(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	u, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	nbf := time.Now()
	tok, err := NewToken(u, &TokenOptions{
		Secret:         "foo",
		NotValidBefore: nbf,
	})
	require.NoError(t, err)
	ptok, err := jwt.Parse([]byte(tok), jwt.WithIssuer("users"), jwt.WithAudience("users"), jwt.WithKey(jwa.HS256(), []byte("foo")))
	require.NoError(t, err)
	require.NotNil(t, ptok)
	nbf2, ok := ptok.NotBefore()
	require.True(t, ok)
	require.WithinDuration(t, nbf, nbf2, 1*time.Second)
}

func Test_that_NewToken_fails_if_Secret_not_set(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	u, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	_, err = NewToken(u, &TokenOptions{})
	require.Error(t, err)
	require.Equal(t, ErrTokenSecretRequired, err)
}

func Test_that_ValidateToken_validates_a_user_token(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	u, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	opts := &TokenOptions{Secret: "foo"}
	tok, err := NewToken(u, opts)
	require.NoError(t, err)
	u2, err := ValidateToken(ctx, client, tok, opts)
	require.NoError(t, err)
	require.NotNil(t, u2)
	require.Equal(t, u.ID, u2.ID)
}

func Test_that_ValidateToken_fails_if_Secret_not_set(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	u, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	opts := &TokenOptions{Secret: "foo"}
	tok, err := NewToken(u, opts)
	require.NoError(t, err)
	opts.Secret = ""
	_, err = ValidateToken(ctx, client, tok, opts)
	require.Error(t, err)
	require.Equal(t, ErrTokenSecretRequired, err)
}

func Test_that_ValidateToken_fails_if_passed_garbage_token(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	opts := &TokenOptions{Secret: "foo"}
	_, err := ValidateToken(ctx, client, "garbage", opts)
	require.Error(t, err)
}

func Test_that_ValidateToken_fails_if_user_does_not_exist_anymore(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	u, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	opts := &TokenOptions{Secret: "foo"}
	tok, err := NewToken(u, opts)
	require.NoError(t, err)
	require.NoError(t, Delete(ctx, client, u))
	_, err = ValidateToken(ctx, client, tok, opts)
	require.Error(t, err)
}
