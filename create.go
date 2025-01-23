package users

import (
	"context"

	"github.com/smxlong/users/ent"
	"github.com/smxlong/users/ent/permission"
	"github.com/smxlong/users/ent/role"
)

// Roles represents all the roles that should exist as well as their permissions.
type Roles map[string]*RoleWithPermissions

// RoleWithPermissions represents a role and its permissions.
type RoleWithPermissions struct {
	Description string
	Permissions []*Permission
}

// Permission represents a role's permission.
type Permission struct {
	Name        string
	Description string
}

// CreateRolesAndPermissions creates all the roles and permissions.
func CreateRolesAndPermissions(ctx context.Context, client *ent.Client, rolesAndPermissions Roles) error {
	// Create a map of permission name to permission. Existing permissions are referenced.
	// Missing permissions are created.
	permissionByName := map[string]*ent.Permission{}
	for _, rolePermissions := range rolesAndPermissions {
		for _, rp := range rolePermissions.Permissions {
			permission, err := FindOrCreatePermission(ctx, client, rp.Name, rp.Description)
			if err != nil {
				return err
			}
			permissionByName[rp.Name] = permission
		}
	}
	// Update each role
	for roleName, rolePermissions := range rolesAndPermissions {
		role, err := FindOrCreateRole(ctx, client, roleName, rolePermissions.Description)
		if err != nil {
			return err
		}
		permissions := make([]*ent.Permission, len(rolePermissions.Permissions))
		for i, rp := range rolePermissions.Permissions {
			permissions[i] = permissionByName[rp.Name]
		}
		_, err = SetRolePermissions(ctx, client, role, permissions)
		if err != nil {
			return err
		}
	}
	return nil
}

// SyncRolesAndPermissions synchronizes the roles and permissions. This calls
// CreateRolesAndPermissions with the given roles and permissions, and then
// deletes any roles or permissions that are not in the given map.
func SyncRolesAndPermissions(ctx context.Context, client *ent.Client, rolesAndPermissions Roles) error {
	// Create the roles and permissions
	if err := CreateRolesAndPermissions(ctx, client, rolesAndPermissions); err != nil {
		return err
	}
	var roleNames []string
	for roleName := range rolesAndPermissions {
		roleNames = append(roleNames, roleName)
	}
	// Delete any roles that are not in the slice
	if _, err := client.Role.Delete().Where(role.NameNotIn(roleNames...)).Exec(ctx); err != nil {
		return err
	}
	// Delete any permissions that aren't part of a role
	if _, err := client.Permission.Delete().Where(permission.Not(permission.HasRoles())).Exec(ctx); err != nil {
		return err
	}
	return nil
}
