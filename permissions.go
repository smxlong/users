package users

import (
	"context"

	"github.com/smxlong/users/ent"
	"github.com/smxlong/users/ent/permission"
)

// CreatePermission creates a permission.
func CreatePermission(ctx context.Context, client *ent.Client, name, description string) (*ent.Permission, error) {
	permission, err := client.Permission.Create().
		SetName(name).
		SetDescription(description).
		Save(ctx)
	if err != nil {
		return nil, err
	}
	return permission, nil
}

// DeletePermission deletes a permission.
func DeletePermission(ctx context.Context, client *ent.Client, permission *ent.Permission) error {
	return client.Permission.DeleteOne(permission).Exec(ctx)
}

// FindOrCreatePermission finds a permission by name or creates it if it doesn't
// exist. If the permission exists but the description doesn't match, an error
// is returned.
func FindOrCreatePermission(ctx context.Context, client *ent.Client, name, description string) (*ent.Permission, error) {
	permission, err := client.Permission.Query().
		Where(permission.Name(name)).
		Only(ctx)
	if err == nil {
		if permission.Description != description {
			return nil, ErrPermissionDescriptionMismatch
		}
		return permission, nil
	}
	if !ent.IsNotFound(err) {
		return nil, err
	}
	return client.Permission.Create().
		SetName(name).
		SetDescription(description).
		Save(ctx)
}

// UpdatePermissionDescription changes a permission's description.
func UpdatePermissionDescription(ctx context.Context, client *ent.Client, permission *ent.Permission, description string) error {
	_, err := permission.Update().
		SetDescription(description).
		Save(ctx)
	return err
}
