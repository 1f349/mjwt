package claims

// EmptyClaims contains no claims
type EmptyClaims struct {}

func (e EmptyClaims) Valid() error { return nil }

func (e EmptyClaims) Type() string { return "empty-claims" }
