package client

import (
	"errors"
	"fmt"
	"github.com/jcmturner/gokrb5/types"
	"strings"
	"time"
)

type Cache struct {
	Entries map[string]CacheEntry
}

type CacheEntry struct {
	Ticket    types.Ticket
	AuthTime  time.Time
	EndTime   time.Time
	RenewTill time.Time
	AutoRenew bool
}

func NewCache() *Cache {
	return &Cache{
		Entries: map[string]CacheEntry{},
	}
}

func (c *Cache) GetEntry(spn string) (CacheEntry, bool) {
	e, ok := (*c).Entries[spn]
	return e, ok
}

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

func (c *Cache) RenewEntry(spn string) error {
	if e, ok := c.GetEntry(spn); ok {
		return e.Renew()
	}
	return fmt.Errorf("No entry for this SPN: %s", spn)
}

func (c *Cache) AddEntry(tkt types.Ticket, authTime, endTime, renewTill time.Time) {
	(*c).Entries[strings.Join(tkt.SName.NameString, "/")] = CacheEntry{
		Ticket:    tkt,
		AuthTime:  authTime,
		EndTime:   endTime,
		RenewTill: renewTill,
	}
}

func (c *Cache) RemoveEntry(spn string) {
	delete(c.Entries, spn)
}

func (c *Cache) EnableAutoRenew(spn string) error {
	return nil
}

func (c *Cache) DisableAutoRenew(spn string) error {
	return nil
}

func (e *CacheEntry) Renew() error {
	if time.Now().After(e.RenewTill) {
		return errors.New("Past renew till time. Cannot renew.")
	}
	//TODO put renew action here
	return nil
}
