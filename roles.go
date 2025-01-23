package users

import (
	"context"

	"github.com/smxlong/users/ent"
)

// CreateRole creates a role and assigns it the given permissions.
func CreateRole(ctx context.Context, client *ent.Client, name, description string, permissions ...*ent.Permission) (*ent.Role, error) {
	role, err := client.Role.Create().
		SetName(name).
		SetDescription(description).
		AddPermissions(permissions...).
		Save(ctx)
	if err != nil {
		return nil, err
	}
	return role, nil
}

// AddRolePermission adds a permission to a role.
func AddRolePermission(ctx context.Context, client *ent.Client, role *ent.Role, permission *ent.Permission) (*ent.Role, error) {
	role, err := role.Update().
		AddPermissions(permission).
		Save(ctx)
	if err != nil {
		return nil, err
	}
	return role, nil
}

// RemoveRolePermission removes a permission from a role.
func RemoveRolePermission(ctx context.Context, client *ent.Client, role *ent.Role, permission *ent.Permission) (*ent.Role, error) {
	role, err := role.Update().
		RemovePermissions(permission).
		Save(ctx)
	if err != nil {
		return nil, err
	}
	return role, nil
}

// DeleteRole deletes a role.
func DeleteRole(ctx context.Context, client *ent.Client, role *ent.Role) error {
	return client.Role.DeleteOne(role).Exec(ctx)
}
