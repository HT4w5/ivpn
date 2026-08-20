package user

import "uuid"

type User struct {
	id                 uuid.UUID
	info               Info
	externelIdentities map[string]ExternalIdentity
}
