package users

import (
	"context"
	"strings"
	"testing"

	"github.com/smxlong/users/ent"
	"github.com/stretchr/testify/require"
)

func Test_that_CreateRole_works_with_no_permissions(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	r, err := CreateRole(ctx, client, "test_role", "Test Role")
	require.NoError(t, err)
	require.NotNil(t, r)
	require.Equal(t, "test_role", r.Name)
	perms, err := r.QueryPermissions().All(ctx)
	require.NoError(t, err)
	require.Empty(t, perms)
}

func Test_that_CreateRole_works_with_one_permission(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	p, err := CreatePermission(ctx, client, "test_permission", "Test Permission")
	require.NoError(t, err)
	r, err := CreateRole(ctx, client, "test_role", "Test Role", p)
	require.NoError(t, err)
	require.NotNil(t, r)
	require.Equal(t, "test_role", r.Name)
	perms, err := r.QueryPermissions().All(ctx)
	require.NoError(t, err)
	require.Len(t, perms, 1)
	require.Equal(t, "test_permission", perms[0].Name)
}

func Test_that_CreateRole_works_with_multiple_permissions(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	p1, err := CreatePermission(ctx, client, "test_permission1", "Test Permission 1")
	require.NoError(t, err)
	p2, err := CreatePermission(ctx, client, "test_permission2", "Test Permission 2")
	require.NoError(t, err)
	r, err := CreateRole(ctx, client, "test_role", "Test Role", p1, p2)
	require.NoError(t, err)
	require.NotNil(t, r)
	require.Equal(t, "test_role", r.Name)
	perms, err := r.QueryPermissions().All(ctx)
	require.NoError(t, err)
	require.Len(t, perms, 2)
	p1 = perms[0]
	p2 = perms[1]
	// sort by name so we don't care about the order they're returned by the query
	if strings.Compare(p1.Name, p2.Name) > 0 {
		p1, p2 = p2, p1
	}
	require.Equal(t, "test_permission1", p1.Name)
	require.Equal(t, "test_permission2", p2.Name)
}

func Test_that_CreateRole_fails_with_duplicate_name(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	_, err := CreateRole(ctx, client, "test_role", "Test Role")
	require.NoError(t, err)
	_, err = CreateRole(ctx, client, "test_role", "Test Role")
	require.Error(t, err)
}

func Test_that_AddRolePermission_works(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	r, err := CreateRole(ctx, client, "test_role", "Test Role")
	require.NoError(t, err)
	p, err := CreatePermission(ctx, client, "test_permission", "Test Permission")
	require.NoError(t, err)
	r, err = AddRolePermission(ctx, client, r, p)
	require.NoError(t, err)
	perms, err := r.QueryPermissions().All(ctx)
	require.NoError(t, err)
	require.Len(t, perms, 1)
	require.Equal(t, "test_permission", perms[0].Name)
}

func Test_that_AddRolePermission_tolerates_duplicate_permissions(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	r, err := CreateRole(ctx, client, "test_role", "Test Role")
	require.NoError(t, err)
	p, err := CreatePermission(ctx, client, "test_permission", "Test Permission")
	require.NoError(t, err)
	r, err = AddRolePermission(ctx, client, r, p)
	require.NoError(t, err)
	r, err = AddRolePermission(ctx, client, r, p)
	require.NoError(t, err)
	perms, err := r.QueryPermissions().All(ctx)
	require.NoError(t, err)
	require.Len(t, perms, 1)
	require.Equal(t, "test_permission", perms[0].Name)
}

func Test_that_AddRolePermission_fails_with_unknown_role(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	r, err := CreateRole(ctx, client, "test_role", "Test Role")
	require.NoError(t, err)
	p, err := CreatePermission(ctx, client, "test_permission", "Test Permission")
	require.NoError(t, err)
	err = client.Role.DeleteOne(r).Exec(ctx)
	require.NoError(t, err)
	_, err = AddRolePermission(ctx, client, r, p)
	require.Error(t, err)
}

func Test_that_AddRolePermission_fails_with_unknown_permission(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	r, err := CreateRole(ctx, client, "test_role", "Test Role")
	require.NoError(t, err)
	p, err := CreatePermission(ctx, client, "test_permission", "Test Permission")
	require.NoError(t, err)
	err = client.Permission.DeleteOne(p).Exec(ctx)
	require.NoError(t, err)
	_, err = AddRolePermission(ctx, client, r, p)
	require.Error(t, err)
}

func Test_that_RemoveRolePermission_works(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	r, err := CreateRole(ctx, client, "test_role", "Test Role")
	require.NoError(t, err)
	p, err := CreatePermission(ctx, client, "test_permission", "Test Permission")
	require.NoError(t, err)
	r, err = AddRolePermission(ctx, client, r, p)
	require.NoError(t, err)
	r, err = RemoveRolePermission(ctx, client, r, p)
	require.NoError(t, err)
	perms, err := r.QueryPermissions().All(ctx)
	require.NoError(t, err)
	require.Empty(t, perms)
}

func Test_that_RemoveRolePermission_tolerates_missing_permissions(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	r, err := CreateRole(ctx, client, "test_role", "Test Role")
	require.NoError(t, err)
	p, err := CreatePermission(ctx, client, "test_permission", "Test Permission")
	require.NoError(t, err)
	r, err = RemoveRolePermission(ctx, client, r, p)
	require.NoError(t, err)
	perms, err := r.QueryPermissions().All(ctx)
	require.NoError(t, err)
	require.Empty(t, perms)
}

func Test_that_RemoveRolePermission_fails_with_unknown_role(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	r, err := CreateRole(ctx, client, "test_role", "Test Role")
	require.NoError(t, err)
	p, err := CreatePermission(ctx, client, "test_permission", "Test Permission")
	require.NoError(t, err)
	err = client.Role.DeleteOne(r).Exec(ctx)
	require.NoError(t, err)
	_, err = RemoveRolePermission(ctx, client, r, p)
	require.Error(t, err)
}

func Test_that_DeleteRole_works(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	r, err := CreateRole(ctx, client, "test_role", "Test Role")
	require.NoError(t, err)
	err = DeleteRole(ctx, client, r)
	require.NoError(t, err)
}

func Test_that_RoleExists_returns_true_for_existing_role(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	_, err := CreateRole(ctx, client, "test_role", "Test Role")
	require.NoError(t, err)
	exists, err := RoleExists(ctx, client, "test_role")
	require.NoError(t, err)
	require.True(t, exists)
}

func Test_that_RoleExists_returns_false_for_missing_role(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	exists, err := RoleExists(ctx, client, "test_role")
	require.NoError(t, err)
	require.False(t, exists)
}

func Test_that_SetRolePermissions_adds_permissions_when_needed(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	r, err := CreateRole(ctx, client, "test_role", "Test Role")
	require.NoError(t, err)
	p1, err := CreatePermission(ctx, client, "test_permission1", "Test Permission 1")
	require.NoError(t, err)
	p2, err := CreatePermission(ctx, client, "test_permission2", "Test Permission 2")
	require.NoError(t, err)
	r, err = SetRolePermissions(ctx, client, r, []*ent.Permission{p1, p2})
	require.NoError(t, err)
	perms, err := r.QueryPermissions().All(ctx)
	require.NoError(t, err)
	require.Len(t, perms, 2)
	p1 = perms[0]
	p2 = perms[1]
	// sort by name so we don't care about the order they're returned by the query
	if strings.Compare(p1.Name, p2.Name) > 0 {
		p1, p2 = p2, p1
	}
	require.Equal(t, "test_permission1", p1.Name)
	require.Equal(t, "test_permission2", p2.Name)
}

func Test_that_SetRolePermissions_removes_permissions_when_needed(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	r, err := CreateRole(ctx, client, "test_role", "Test Role")
	require.NoError(t, err)
	p1, err := CreatePermission(ctx, client, "test_permission1", "Test Permission 1")
	require.NoError(t, err)
	p2, err := CreatePermission(ctx, client, "test_permission2", "Test Permission 2")
	require.NoError(t, err)
	r, err = AddRolePermission(ctx, client, r, p1)
	require.NoError(t, err)
	r, err = SetRolePermissions(ctx, client, r, []*ent.Permission{p2})
	require.NoError(t, err)
	perms, err := r.QueryPermissions().All(ctx)
	require.NoError(t, err)
	require.Len(t, perms, 1)
	require.Equal(t, "test_permission2", perms[0].Name)
}

func Test_that_SetRolePermissions_clears_all_permissions_when_needed(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	r, err := CreateRole(ctx, client, "test_role", "Test Role")
	require.NoError(t, err)
	p1, err := CreatePermission(ctx, client, "test_permission1", "Test Permission 1")
	require.NoError(t, err)
	p2, err := CreatePermission(ctx, client, "test_permission2", "Test Permission 2")
	require.NoError(t, err)
	r, err = AddRolePermission(ctx, client, r, p1)
	require.NoError(t, err)
	r, err = SetRolePermissions(ctx, client, r, []*ent.Permission{p2})
	require.NoError(t, err)
	r, err = SetRolePermissions(ctx, client, r, nil)
	require.NoError(t, err)
	perms, err := r.QueryPermissions().All(ctx)
	require.NoError(t, err)
	require.Empty(t, perms)
}

func Test_that_FindOrCreateRole_creates_role_if_it_does_not_exist(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	r, err := FindOrCreateRole(ctx, client, "test_role", "Test Role")
	require.NoError(t, err)
	require.NotNil(t, r)
	require.Equal(t, "test_role", r.Name)
}

func Test_that_FindOrCreateRole_finds_role_if_it_exists(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	r, err := CreateRole(ctx, client, "test_role", "Test Role")
	require.NoError(t, err)
	r2, err := FindOrCreateRole(ctx, client, "test_role", "Test Role")
	require.NoError(t, err)
	require.NotNil(t, r2)
	require.Equal(t, r.ID, r2.ID)
}

func Test_that_FindOrCreateRole_updates_description_if_it_exists(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	r, err := CreateRole(ctx, client, "test_role", "Test Role")
	require.NoError(t, err)
	r2, err := FindOrCreateRole(ctx, client, "test_role", "Test Role 2")
	require.NoError(t, err)
	require.NotNil(t, r2)
	require.Equal(t, r.ID, r2.ID)
	require.Equal(t, "Test Role 2", r2.Description)
}

func Test_that_UpdateRoleDescription_works(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	r, err := CreateRole(ctx, client, "test_role", "Test Role")
	require.NoError(t, err)
	err = UpdateRoleDescription(ctx, client, r, "Test Role 2")
	require.NoError(t, err)
	r2, err := client.Role.Get(ctx, r.ID)
	require.NoError(t, err)
	require.Equal(t, "Test Role 2", r2.Description)
}
