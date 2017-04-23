package mstypes

// https://msdn.microsoft.com/en-us/library/cc237950.aspx
type PACType struct {
	CBuffers uint32
	Verion   uint32
	Buffers  []PACInfoBuffer
}
