package users

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_that_CreatePermission_works(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	p, err := CreatePermission(ctx, client, "test_permission", "Test Permission")
	require.NoError(t, err)
	require.NotNil(t, p)
	require.Equal(t, "test_permission", p.Name)
}

func Test_that_CreatePermission_fails_with_duplicate_name(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	_, err := CreatePermission(ctx, client, "test_permission", "Test Permission")
	require.NoError(t, err)
	_, err = CreatePermission(ctx, client, "test_permission", "Test Permission")
	require.Error(t, err)
}

func Test_that_DeletePermission_works(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	p, err := CreatePermission(ctx, client, "test_permission", "Test Permission")
	require.NoError(t, err)
	err = DeletePermission(ctx, client, p)
	require.NoError(t, err)
}

func Test_that_DeletePermission_fails_with_unknown_permission(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	p, err := CreatePermission(ctx, client, "test_permission", "Test Permission")
	require.NoError(t, err)
	err = DeletePermission(ctx, client, p)
	require.NoError(t, err)
	err = DeletePermission(ctx, client, p)
	require.Error(t, err)
}

func Test_that_FindOrCreatePermission_creates_permission_if_it_does_not_exist(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	p, err := FindOrCreatePermission(ctx, client, "test_permission", "Test Permission")
	require.NoError(t, err)
	require.NotNil(t, p)
	require.Equal(t, "test_permission", p.Name)
}

func Test_that_FindOrCreatePermission_finds_permission_if_it_exists(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	p, err := CreatePermission(ctx, client, "test_permission", "Test Permission")
	require.NoError(t, err)
	p2, err := FindOrCreatePermission(ctx, client, "test_permission", "Test Permission")
	require.NoError(t, err)
	require.NotNil(t, p2)
	require.Equal(t, p.ID, p2.ID)
}

func Test_that_FindOrCreatePermission_fails_if_description_mismatch(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	_, err := CreatePermission(ctx, client, "test_permission", "Test Permission")
	require.NoError(t, err)
	_, err = FindOrCreatePermission(ctx, client, "test_permission", "Test Permission2")
	require.Error(t, err)
}

func Test_that_UpdatePermissionDescription_works(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	p, err := CreatePermission(ctx, client, "test_permission", "Test Permission")
	require.NoError(t, err)
	err = UpdatePermissionDescription(ctx, client, p, "Test Permission2")
	require.NoError(t, err)
	p2, err := client.Permission.Get(ctx, p.ID)
	require.NoError(t, err)
	require.Equal(t, "Test Permission2", p2.Description)
}
