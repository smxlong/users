package users

import (
	"context"

	"github.com/smxlong/users/ent"
	"github.com/smxlong/users/ent/role"
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

// RoleExists checks if a role exists.
func RoleExists(ctx context.Context, client *ent.Client, name string) (bool, error) {
	_, err := client.Role.Query().
		Where(role.Name(name)).
		Only(ctx)
	if ent.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// SetRolePermissions sets a role's permissions to exactly the given permissions.
func SetRolePermissions(ctx context.Context, client *ent.Client, role *ent.Role, permissions []*ent.Permission) (*ent.Role, error) {
	role, err := role.Update().
		ClearPermissions().
		AddPermissions(permissions...).
		Save(ctx)
	if err != nil {
		return nil, err
	}
	return role, nil
}

// FindOrCreateRole finds a role by name or creates it if it doesn't exist. If
// the role exists but the description doesn't match, the description is
// updated.
func FindOrCreateRole(ctx context.Context, client *ent.Client, name, description string) (*ent.Role, error) {
	role, err := client.Role.Query().
		Where(role.Name(name)).
		Only(ctx)
	if err == nil {
		if role.Description != description {
			role, err = role.Update().
				SetDescription(description).
				Save(ctx)
			if err != nil {
				return nil, err
			}
		}
		return role, nil
	}
	if !ent.IsNotFound(err) {
		return nil, err
	}
	return client.Role.Create().
		SetName(name).
		SetDescription(description).
		Save(ctx)
}

// UpdateRoleDescription changes a role's description.
func UpdateRoleDescription(ctx context.Context, client *ent.Client, role *ent.Role, description string) error {
	_, err := role.Update().
		SetDescription(description).
		Save(ctx)
	return err
}
