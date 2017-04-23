package mstypes

// https://msdn.microsoft.com/en-us/library/cc237944.aspx
type S4U_DelegationInfo struct {
	S4U2proxyTarget      RPC_UnicodeString // The name of the principal to whom the application can forward the ticket.
	TransitedListSize    uint32
	S4UTransitedServices []RPC_UnicodeString // List of all services that have been delegated through by this client and subsequent services or servers.. Size is value of TransitedListSize
}
