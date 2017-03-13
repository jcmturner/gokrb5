package client

import (
	"github.com/jcmturner/gokrb5/types"
	"strings"
	"time"
)

// Client ticket cache.
type Cache struct {
	Entries map[string]CacheEntry
}

// Ticket cache entry.
type CacheEntry struct {
	Ticket    types.Ticket
	AuthTime  time.Time
	EndTime   time.Time
	RenewTill time.Time
}

// Create a new client ticket cache.
func NewCache() *Cache {
	return &Cache{
		Entries: map[string]CacheEntry{},
	}
}

// Get a cache entry that matches the SPN.
func (c *Cache) GetEntry(spn string) (CacheEntry, bool) {
	e, ok := (*c).Entries[spn]
	return e, ok
}

// Get a ticket from the cache for the SPN.
// Only a ticket that is currently valid will be returned.
func (c *Cache) GetTicket(spn string) (types.Ticket, bool) {
	if e, ok := c.GetEntry(spn); ok {
		//If within time window of ticket return it
		if time.Now().After(e.AuthTime) && time.Now().Before(e.EndTime) {
			return e.Ticket, true
		}
	}
	var tkt types.Ticket
	return tkt, false
}

// Add a ticket to the cache.
func (c *Cache) AddEntry(tkt types.Ticket, authTime, endTime, renewTill time.Time) {
	(*c).Entries[strings.Join(tkt.SName.NameString, "/")] = CacheEntry{
		Ticket:    tkt,
		AuthTime:  authTime,
		EndTime:   endTime,
		RenewTill: renewTill,
	}
}

// Remove the cache entry for the defined SPN.
func (c *Cache) RemoveEntry(spn string) {
	delete(c.Entries, spn)
}

// Renew a ticket in the cache for the specified SPN.
//func (c *Cache) RenewEntry(spn string) error {
//	if e, ok := c.GetEntry(spn); ok {
//		return e.Renew()
//	}
//	return fmt.Errorf("No entry for this SPN: %s", spn)
//}

// Enable background auto renew of the ticket for the specified SPN.
//func (cl *Client) EnableAutoRenew(spn string) {
//	go func() {
//		for {
//
//		}
//	}()
//}

// Renew the cache entry.
//func (e *CacheEntry) Renew() error {
//	if time.Now().After(e.RenewTill) {
//		return errors.New("Past renew till time. Cannot renew.")
//	}
//	//TODO put renew action here
//	return nil
//}
