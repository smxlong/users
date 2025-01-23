package users

import (
	"context"

	"github.com/smxlong/users/ent"
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
