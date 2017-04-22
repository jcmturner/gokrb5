package mstypes

const (
	SE_GROUP_MANDATORY          = 31
	SE_GROUP_ENABLED_BY_DEFAULT = 30
	SE_GROUP_ENABLED            = 29
	SE_GROUP_OWNER              = 28
	SE_GROUP_RESOURCE           = 2
	//All other bits MUST be set to zero and MUST be  ignored on receipt.
)

// https://msdn.microsoft.com/en-us/library/cc237947.aspx
type KerbSidAndAttributes struct {
	SID        RPC_SID // A pointer to an RPC_SID structure.
	Attributes ULong
}

func SetFlag(a *ULong, i uint) {
	*a = *a | (1 << (31 - i))
}
