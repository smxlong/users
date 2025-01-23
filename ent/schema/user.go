package schema

import (
	"net/mail"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// User holds the schema definition for the User entity.
type User struct {
	ent.Schema
}

// Fields of the User.
func (User) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").
			NotEmpty().
			Unique(),
		field.String("email").
			NotEmpty().
			Validate(emailValidator).
			Unique(),
		field.String("password_hash").
			NotEmpty(),
	}
}

// Edges of the User.
func (User) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("roles", Role.Type),
	}
}

type errEmailAddressInvalid string

func (e errEmailAddressInvalid) Error() string {
	return string(e)
}

const (
	ErrEmailAddressInvalid errEmailAddressInvalid = "invalid email address"
)

func emailValidator(s string) error {
	addr, err := mail.ParseAddress(s)
	if err == nil && addr.Address == "" {
		err = ErrEmailAddressInvalid
	}
	return err
}
