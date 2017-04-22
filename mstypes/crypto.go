package mstypes

type CypherBlock struct {
	Data []byte // size = 8
}

type UserSessionKey struct {
	Data []CypherBlock // size = 2
}
