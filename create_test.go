package users

import (
	"context"
	"sort"
	"testing"

	"github.com/smxlong/users/ent/role"
	"github.com/stretchr/testify/require"
)

var testRolesAndPermissions = Roles{
	"admin": &RoleWithPermissions{
		Description: "Admin role",
		Permissions: []*Permission{
			{
				Name:        "admin",
				Description: "Admin permission",
			},
		},
	},
	"user": &RoleWithPermissions{
		Description: "User role",
		Permissions: []*Permission{
			{
				Name:        "user",
				Description: "User permission",
			},
		},
	},
}

var testMoreRolesAndPermissions = Roles{
	"admin": &RoleWithPermissions{
		Description: "Admin role",
		Permissions: []*Permission{
			{
				Name:        "admin",
				Description: "Admin permission",
			},
		},
	},
	"user": &RoleWithPermissions{
		Description: "User role",
		Permissions: []*Permission{
			{
				Name:        "user",
				Description: "User permission",
			},
		},
	},
	"x": &RoleWithPermissions{
		Description: "X role",
		Permissions: []*Permission{
			{
				Name:        "x",
				Description: "X permission",
			},
		},
	},
}

func Test_that_CreateRolesAndPermissions_works(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	// run this block twice to ensure idempotency
	for i := 0; i < 2; i++ {
		err := CreateRolesAndPermissions(ctx, client, testRolesAndPermissions)
		require.NoError(t, err)
		n, err := client.Role.Query().Count(ctx)
		require.NoError(t, err)
		require.Equal(t, 2, n)
		for roleName, rolePermissions := range testRolesAndPermissions {
			role, err := client.Role.Query().Where(role.Name(roleName)).Only(ctx)
			require.NoError(t, err)
			require.NotNil(t, role)
			require.Equal(t, rolePermissions.Description, role.Description)
			rolePerms, err := role.QueryPermissions().All(ctx)
			require.NoError(t, err)
			require.Len(t, rolePerms, len(rolePermissions.Permissions))
			// sort the perms by name - admin comes before user
			sort.Slice(rolePerms, func(i, j int) bool {
				return rolePerms[i].Name < rolePerms[j].Name
			})
			for i, rp := range rolePermissions.Permissions {
				require.Equal(t, rp.Name, rolePerms[i].Name)
				require.Equal(t, rp.Description, rolePerms[i].Description)
			}
		}
	}
}

func Test_that_CreateRolesAndPermissions_fails_with_mismatched_permission_descriptions(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	testRolesAndPermissions := Roles{
		"admin": &RoleWithPermissions{
			Description: "Admin role",
			Permissions: []*Permission{
				{
					Name:        "admin",
					Description: "Admin permission",
				},
			},
		},
		"user": &RoleWithPermissions{
			Description: "User role",
			Permissions: []*Permission{
				{
					Name:        "user",
					Description: "User permission",
				},
				{
					Name:        "admin",
					Description: "Admin permission 2",
				},
			},
		},
	}
	err := CreateRolesAndPermissions(ctx, client, testRolesAndPermissions)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrPermissionDescriptionMismatch)
}

func Test_that_SyncRolesAndPermissions_works_when_removing_roles(t *testing.T) {
	client := setupAndMigrate(t)
	ctx := context.Background()
	err := CreateRolesAndPermissions(ctx, client, testMoreRolesAndPermissions)
	require.NoError(t, err)
	n, err := client.Role.Query().Count(ctx)
	require.NoError(t, err)
	require.Equal(t, 3, n)
	err = SyncRolesAndPermissions(ctx, client, testRolesAndPermissions)
	require.NoError(t, err)
	n, err = client.Role.Query().Count(ctx)
	require.NoError(t, err)
	require.Equal(t, 2, n)
	err = SyncRolesAndPermissions(ctx, client, Roles{})
	require.NoError(t, err)
	n, err = client.Role.Query().Count(ctx)
	require.NoError(t, err)
	require.Equal(t, 0, n)
}
