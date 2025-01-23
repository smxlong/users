package users

import (
	"context"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/smxlong/users/ent"
)

const USER1_TEST_EMAIL = "user1@example.com"
const USER2_TEST_EMAIL = "user2@example.com"

func setup(t *testing.T) *ent.Client {
	client, err := ent.Open("sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
	})
	return client
}

func setupAndMigrate(t *testing.T) *ent.Client {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := setup(t)
	err := client.Schema.Create(ctx)
	require.NoError(t, err)
	return client
}

func Test_that_Schema_Create_works(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := setup(t)
	err := client.Schema.Create(ctx)
	require.NoError(t, err)
}

func Test_that_CreateUser_works(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	uout, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	u := client.User.GetX(ctx, uout.ID)
	require.NotNil(t, u)
	require.Equal(t, "user1", u.Name)
	require.Equal(t, USER1_TEST_EMAIL, u.Email)
	ph, err := PasswordHashParse(u.PasswordHash)
	require.NoError(t, err)
	require.NoError(t, ph.Verify("password"))
}

func Test_that_CreateUser_fails_with_duplicate_email(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	_, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	_, err = Create(ctx, client, "user2", USER1_TEST_EMAIL, "password")
	require.Error(t, err)
}

func Test_that_CreateUser_fails_with_duplicate_name(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	_, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	_, err = Create(ctx, client, "user1", USER2_TEST_EMAIL, "password")
	require.Error(t, err)
}

func Test_that_CreateUser_fails_with_password_too_long(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	_, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "a very long password that is longer than 72 characters and should return an error because bcrypt only supports 72 characters")
	require.ErrorIs(t, err, bcrypt.ErrPasswordTooLong)
}

func Test_that_CreateUser_fails_with_invalid_email(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	_, err := Create(ctx, client, "user1", "not an email", "password")
	require.Error(t, err)
}

func Test_that_FindByName_works(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	_, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	u, err := FindByName(ctx, client, "user1")
	require.NoError(t, err)
	require.NotNil(t, u)
	require.Equal(t, "user1", u.Name)
	require.Equal(t, USER1_TEST_EMAIL, u.Email)
	ph, err := PasswordHashParse(u.PasswordHash)
	require.NoError(t, err)
	require.NoError(t, ph.Verify("password"))
}

func Test_that_FindByName_fails_with_unknown_name(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	_, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	_, err = FindByName(ctx, client, "user2")
	require.Error(t, err)
}

func Test_that_FindByEmail_works(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	_, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	u, err := FindByEmail(ctx, client, USER1_TEST_EMAIL)
	require.NoError(t, err)
	require.NotNil(t, u)
	require.Equal(t, "user1", u.Name)
	require.Equal(t, USER1_TEST_EMAIL, u.Email)
	ph, err := PasswordHashParse(u.PasswordHash)
	require.NoError(t, err)
	require.NoError(t, ph.Verify("password"))
}

func Test_that_FindByEmail_fails_with_unknown_email(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	_, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	_, err = FindByEmail(ctx, client, USER2_TEST_EMAIL)
	require.Error(t, err)
}

func Test_that_LoginByName_works(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	_, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	u, err := LoginByName(ctx, client, "user1", "password")
	require.NoError(t, err)
	require.NotNil(t, u)
	require.Equal(t, "user1", u.Name)
	require.Equal(t, USER1_TEST_EMAIL, u.Email)
}

func Test_that_LoginByName_fails_with_unknown_name(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	_, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	_, err = LoginByName(ctx, client, "user2", "password")
	require.Error(t, err)
}

func Test_that_LoginByName_fails_with_wrong_password(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	_, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	_, err = LoginByName(ctx, client, "user1", "wrong password")
	require.Error(t, err)
}

func Test_that_LoginByEmail_works(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	_, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	u, err := LoginByEmail(ctx, client, USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	require.NotNil(t, u)
	require.Equal(t, "user1", u.Name)
	require.Equal(t, USER1_TEST_EMAIL, u.Email)
}

func Test_that_LoginByEmail_fails_with_unknown_email(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	_, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	_, err = LoginByEmail(ctx, client, USER2_TEST_EMAIL, "password")
	require.Error(t, err)
}

func Test_that_LoginByEmail_fails_with_wrong_password(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	_, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	_, err = LoginByEmail(ctx, client, USER1_TEST_EMAIL, "wrong password")
	require.Error(t, err)
}

func Test_that_Login_works(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	_, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	u, err := FindByName(ctx, client, "user1")
	require.NoError(t, err)
	u, err = Login(ctx, u, "password")
	require.NoError(t, err)
	require.NotNil(t, u)
	require.Equal(t, "user1", u.Name)
	require.Equal(t, USER1_TEST_EMAIL, u.Email)
}

func Test_that_Login_fails_with_wrong_password(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	_, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	u, err := FindByName(ctx, client, "user1")
	require.NoError(t, err)
	_, err = Login(ctx, u, "wrong password")
	require.Error(t, err)
}

func Test_that_Login_fails_with_corrupted_password_hash(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	_, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	u, err := FindByName(ctx, client, "user1")
	require.NoError(t, err)
	u.PasswordHash = "corrupted"
	_, err = Login(ctx, u, "password")
	// this just proves that an if statement can be reached
	require.Error(t, err)
}

func Test_that_AddRole_works(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	u, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	r, err := CreateRole(ctx, client, "test_role", "Test Role")
	require.NoError(t, err)
	u, err = AddRole(ctx, client, u, r)
	require.NoError(t, err)
	roles, err := u.QueryRoles().All(ctx)
	require.NoError(t, err)
	require.Len(t, roles, 1)
	require.Equal(t, "test_role", roles[0].Name)
}

func Test_that_AddRole_fails_with_unknown_role(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	u, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	r, err := CreateRole(ctx, client, "test_role", "Test Role")
	require.NoError(t, err)
	err = client.Role.DeleteOne(r).Exec(ctx)
	require.NoError(t, err)
	_, err = AddRole(ctx, client, u, r)
	require.Error(t, err)
}

func Test_that_AddRole_tolerates_duplicate_roles(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	u, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	r, err := CreateRole(ctx, client, "test_role", "Test Role")
	require.NoError(t, err)
	u, err = AddRole(ctx, client, u, r)
	require.NoError(t, err)
	u, err = AddRole(ctx, client, u, r)
	require.NoError(t, err)
	roles, err := u.QueryRoles().All(ctx)
	require.NoError(t, err)
	require.Len(t, roles, 1)
	require.Equal(t, "test_role", roles[0].Name)
}

func Test_that_RemoveRole_works(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	u, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	r, err := CreateRole(ctx, client, "test_role", "Test Role")
	require.NoError(t, err)
	u, err = AddRole(ctx, client, u, r)
	require.NoError(t, err)
	u, err = RemoveRole(ctx, client, u, r)
	require.NoError(t, err)
	roles, err := u.QueryRoles().All(ctx)
	require.NoError(t, err)
	require.Len(t, roles, 0)
}

func Test_that_RemoveRole_tolerates_unknown_roles(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	u, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	r, err := CreateRole(ctx, client, "test_role", "Test Role")
	require.NoError(t, err)
	err = client.Role.DeleteOne(r).Exec(ctx)
	require.NoError(t, err)
	_, err = RemoveRole(ctx, client, u, r)
	require.NoError(t, err)
}

func Test_that_CheckPermission_works(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	u, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	r, err := CreateRole(ctx, client, "test_role", "Test Role")
	require.NoError(t, err)
	p, err := CreatePermission(ctx, client, "test_permission", "Test Permission")
	require.NoError(t, err)
	r, err = AddRolePermission(ctx, client, r, p)
	require.NoError(t, err)
	u, err = AddRole(ctx, client, u, r)
	require.NoError(t, err)
	ok, err := CheckPermission(ctx, client, u, "test_permission")
	require.NoError(t, err)
	require.True(t, ok)
}

func Test_that_CheckPermission_fails_with_missing_permission(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	u, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	ok, err := CheckPermission(ctx, client, u, "test_permission")
	require.NoError(t, err)
	require.False(t, ok)
}

func Test_that_CheckPermission_checks_multiple_permissions(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	u, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	r, err := CreateRole(ctx, client, "test_role", "Test Role")
	require.NoError(t, err)
	p1, err := CreatePermission(ctx, client, "test_permission1", "Test Permission 1")
	require.NoError(t, err)
	p2, err := CreatePermission(ctx, client, "test_permission2", "Test Permission 2")
	require.NoError(t, err)
	r, err = AddRolePermission(ctx, client, r, p1)
	require.NoError(t, err)
	r, err = AddRolePermission(ctx, client, r, p2)
	require.NoError(t, err)
	u, err = AddRole(ctx, client, u, r)
	require.NoError(t, err)
	ok, err := CheckPermission(ctx, client, u, "test_permission1", "test_permission2")
	require.NoError(t, err)
	require.True(t, ok)
}

func Test_that_CheckPermission_fails_with_missing_permissions(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	u, err := Create(ctx, client, "user1", USER1_TEST_EMAIL, "password")
	require.NoError(t, err)
	r, err := CreateRole(ctx, client, "test_role", "Test Role")
	require.NoError(t, err)
	p1, err := CreatePermission(ctx, client, "test_permission1", "Test Permission 1")
	require.NoError(t, err)
	_, err = CreatePermission(ctx, client, "test_permission2", "Test Permission 2")
	require.NoError(t, err)
	r, err = AddRolePermission(ctx, client, r, p1)
	require.NoError(t, err)
	u, err = AddRole(ctx, client, u, r)
	require.NoError(t, err)
	ok, err := CheckPermission(ctx, client, u, "test_permission1", "test_permission2")
	require.NoError(t, err)
	require.False(t, ok)
}
