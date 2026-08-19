package user

type Info struct {
	email string
}

func (i *Info) Email() string {
	return i.email
}
