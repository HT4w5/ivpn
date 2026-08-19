package user

import "github.com/google/uuid"

type User struct {
	id                 uuid.UUID
	info               Info
	externelIdentities map[string]ExternalIdentity
}
