package access

import (
	"errors"
	"fmt"
	"time"

	"github.com/HT4w5/ivpn/internal/domain/acl"
	"github.com/google/uuid"
)

type ID uuid.UUID
type UserID uuid.UUID

type Key struct {
	createdAt     time.Time
	expiresAt     time.Time // Zero value = never expires
	name          string
	method        Method
	secret        Secret
	aclRules      []acl.Rule
	id            ID
	userID        UserID
	defaultAction acl.Action
}

func NewKey(
	name string,
	userID UserID,
	method Method,
	aclRules []acl.Rule,
	defaultAction acl.Action,
	ttl time.Duration,
) (*Key, error) {
	if name == "" {
		return nil, errors.New("empty name")
	}

	if !method.IsKnown() {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedMethod, method)
	}

	if ttl < 0 {
		return nil, fmt.Errorf("invalid ttl: %s", ttl.String())
	}

	if !defaultAction.IsValid() {
		return nil, fmt.Errorf("invalid default action: %s", defaultAction.String())
	}

	secret, _ := GenerateSecret(method) // Error not possible.

	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("failed to generate id: %w", err)
	}

	createdAt := time.Now().UTC()
	var expiresAt time.Time
	if ttl == 0 {
		expiresAt = time.Time{}
	} else {
		expiresAt = createdAt.Add(ttl)
	}

	return &Key{
		createdAt:     createdAt,
		expiresAt:     expiresAt,
		name:          name,
		method:        method,
		secret:        secret,
		aclRules:      aclRules,
		id:            ID(id),
		userID:        userID,
		defaultAction: defaultAction,
	}, nil
}

func Reconstitute(
	id ID,
	userID UserID,
	name string,
	method Method,
	secret Secret,
	aclRules []acl.Rule,
	defaultAction acl.Action,
	createdAt, expiresAt time.Time,
) *Key {
	return &Key{
		id:            id,
		userID:        userID,
		name:          name,
		method:        method,
		secret:        secret,
		aclRules:      aclRules,
		defaultAction: defaultAction,
		createdAt:     createdAt,
		expiresAt:     expiresAt,
	}
}

var (
	ErrKeyExpired      = errors.New("key expired")
	ErrKeyIncompatible = errors.New("key incompatible with server method")
)

func (k *Key) IsUsable(at time.Time, serverMethod Method) error {
	if !k.IsCompatibleWith(serverMethod) {
		return ErrKeyIncompatible
	}
	if k.IsExpired(at) {
		return ErrKeyExpired
	}
	return nil
}

func (k *Key) IsCompatibleWith(serverMethod Method) bool {
	return k.method == serverMethod
}

func (k *Key) IsExpired(at time.Time) bool {
	if k.expiresAt.IsZero() {
		return false
	} else {
		return at.After(k.expiresAt)
	}
}

// Getters
func (k *Key) ID() ID                    { return k.id }
func (k *Key) UserID() UserID            { return k.userID }
func (k *Key) Name() string              { return k.name }
func (k *Key) Method() Method            { return k.method }
func (k *Key) Secret() Secret            { return k.secret }
func (k *Key) DefaultAction() acl.Action { return k.defaultAction }
func (k *Key) CreatedAt() time.Time      { return k.createdAt }
func (k *Key) ExpiresAt() time.Time      { return k.expiresAt }
func (k *Key) ACLRules() []acl.Rule {
	cp := make([]acl.Rule, len(k.aclRules))
	copy(cp, k.aclRules)
	return cp
}
