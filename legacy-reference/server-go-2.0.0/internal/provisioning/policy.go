package provisioning

// Username is one of the fixed FedMes family accounts.
type Username string

const (
	UserGrisha Username = "grisha"
	UserPapa   Username = "papa"
	UserMama   Username = "mama"
	UserYura   Username = "yura"
	UserVasya  Username = "vasya"
)

var fixedUserSet = map[Username]struct{}{
	UserGrisha: {},
	UserPapa:   {},
	UserMama:   {},
	UserYura:   {},
	UserVasya:  {},
}

var fixedUserOrder = [...]Username{
	UserGrisha,
	UserPapa,
	UserMama,
	UserYura,
	UserVasya,
}

// ParseUsername rejects case folding and whitespace normalization so every
// layer uses one unambiguous account identifier.
func ParseUsername(value string) (Username, error) {
	username := Username(value)
	if _, ok := fixedUserSet[username]; !ok {
		return "", newError(CodeUnknownUser, "username")
	}
	return username, nil
}

func isFixedUser(username Username) bool {
	_, ok := fixedUserSet[username]
	return ok
}

// FixedUsers returns a copy that callers may safely modify.
func FixedUsers() []Username {
	users := make([]Username, len(fixedUserOrder))
	copy(users, fixedUserOrder[:])
	return users
}
