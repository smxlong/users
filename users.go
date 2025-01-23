package users

import (
	"context"

	"github.com/smxlong/users/ent"
	"github.com/smxlong/users/ent/permission"
	"github.com/smxlong/users/ent/user"
)

// These functions are for example only - you'll need to copy them into your
// project to work on your own generated types.

// Create a user from name, email, and password, hashing the password.
func Create(ctx context.Context, client *ent.Client, name, email, password string) (*ent.User, error) {
	ph, err := PasswordHashDefault(password)
	if err != nil {
		return nil, err
	}
	return client.User.Create().
		SetName(name).
		SetEmail(email).
		SetPasswordHash(ph.String()).
		Save(ctx)
}

// FindByName finds a user by name.
func FindByName(ctx context.Context, client *ent.Client, name string) (*ent.User, error) {
	return client.User.Query().
		Where(user.Name(name)).
		Only(ctx)
}

// FindByEmail finds a user by email.
func FindByEmail(ctx context.Context, client *ent.Client, email string) (*ent.User, error) {
	return client.User.Query().
		Where(user.Email(email)).
		Only(ctx)
}

// LoginByName finds a user by name and verifies the password.
func LoginByName(ctx context.Context, client *ent.Client, name, password string) (*ent.User, error) {
	u, err := FindByName(ctx, client, name)
	if err != nil {
		return nil, err
	}
	return Login(ctx, u, password)
}

// LoginByEmail finds a user by email and verifies the password.
func LoginByEmail(ctx context.Context, client *ent.Client, email, password string) (*ent.User, error) {
	u, err := FindByEmail(ctx, client, email)
	if err != nil {
		return nil, err
	}
	return Login(ctx, u, password)
}

// Login verifies the password for a user.
func Login(ctx context.Context, u *ent.User, password string) (*ent.User, error) {
	ph, err := PasswordHashParse(u.PasswordHash)
	if err != nil {
		return nil, err
	}
	if err := ph.Verify(password); err != nil {
		return nil, err
	}
	return u, nil
}

// AddRole adds a role to a user.
func AddRole(ctx context.Context, client *ent.Client, u *ent.User, role *ent.Role) (*ent.User, error) {
	u, err := u.Update().
		AddRoles(role).
		Save(ctx)
	if err != nil {
		return nil, err
	}
	return u, nil
}

// RemoveRole removes a role from a user.
func RemoveRole(ctx context.Context, client *ent.Client, u *ent.User, role *ent.Role) (*ent.User, error) {
	u, err := u.Update().
		RemoveRoles(role).
		Save(ctx)
	if err != nil {
		return nil, err
	}
	return u, nil
}

// CheckPermission checks if a user has all the listed permissions.
func CheckPermission(ctx context.Context, client *ent.Client, u *ent.User, p ...string) (bool, error) {
	count, err := u.QueryRoles().QueryPermissions().
		Where(permission.NameIn(p...)).
		Count(ctx)
	if err != nil {
		return false, err
	}
	return count == len(p), nil
}

// Delete a user.
func Delete(ctx context.Context, client *ent.Client, u *ent.User) error {
	return client.User.DeleteOne(u).Exec(ctx)
}
