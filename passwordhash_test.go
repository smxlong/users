package users

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func Test_that_PasswordHashDefault_hashes_passwords(t *testing.T) {
	ph, err := PasswordHashDefault("password")
	require.NoError(t, err)
	require.NotNil(t, ph)
	require.Equal(t, "bcrypt", ph.Algorithm)
	require.NoError(t, ph.Verify("password"))
	require.ErrorIs(t, ph.Verify("wrong"), ErrPasswordHashMismatch)
}

func Test_that_PasswordHashDefault_returns_error_with_password_longer_than_72_characters(t *testing.T) {
	ph, err := PasswordHashDefault("a very long password that is longer than 72 characters and should return an error because bcrypt only supports 72 characters")
	require.ErrorIs(t, err, bcrypt.ErrPasswordTooLong)
	require.Nil(t, ph)
}

func Test_that_PasswordHashParse_parses_hashes(t *testing.T) {
	ph, err := PasswordHashDefault("password")
	require.NoError(t, err)
	require.NotNil(t, ph)

	s := ph.String()
	require.NotEmpty(t, s)

	ph2, err := PasswordHashParse(s)
	require.NoError(t, err)
	require.NotNil(t, ph2)

	require.Equal(t, ph.Algorithm, ph2.Algorithm)
	require.Equal(t, ph.Hash, ph2.Hash)
}

func Test_that_PasswordHashParse_returns_error_on_invalid_base64(t *testing.T) {
	_, err := PasswordHashParse("*********")
	require.Error(t, err)
}

func Test_that_PasswordHashParse_returns_error_on_invalid_json(t *testing.T) {
	badJson := base64.StdEncoding.EncodeToString([]byte("bad json"))
	_, err := PasswordHashParse(badJson)
	require.Error(t, err)
}

func Test_that_PasswordHash_Verify_returns_error_on_unknown_algorithm(t *testing.T) {
	ph := &PasswordHash{
		Algorithm: "unknown",
	}
	require.ErrorIs(t, ph.Verify("password"), ErrPasswordHashUnknownAlgorithm)
}
