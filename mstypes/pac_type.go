package mstypes

// https://msdn.microsoft.com/en-us/library/cc237950.aspx
type PACType struct {
	CBuffers ULong
	Verion   ULong
	Buffers  []PACInfoBuffer
}
