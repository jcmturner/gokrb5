package service

import (
	"github.com/jcmturner/gokrb5/types"
	"sync"
	"time"
)

/*The server MUST utilize a replay cache to remember any authenticator
presented within the allowable clock skew.
The replay cache will store at least the server name, along with the
client name, time, and microsecond fields from the recently-seen
authenticators, and if a matching tuple is found, the
KRB_AP_ERR_REPEAT error is returned.  Note that the rejection here is
restricted to authenticators from the same principal to the same
server.  Other client principals communicating with the same server
principal should not have their authenticators rejected if the time
and microsecond fields happen to match some other client's
authenticator.

If a server loses track of authenticators presented within the
allowable clock skew, it MUST reject all requests until the clock
skew interval has passed, providing assurance that any lost or
replayed authenticators will fall outside the allowable clock skew
and can no longer be successfully replayed.  If this were not done,
an attacker could subvert the authentication by recording the ticket
and authenticator sent over the network to a server and replaying
them following an event that caused the server to lose track of
recently seen authenticators.*/

type ServiceCache map[string]ClientEntries

type ClientEntries struct {
	ReplayMap map[time.Time]ReplayCacheEntry
	SeqNumber int
	SubKey    types.EncryptionKey
}

type ReplayCacheEntry struct {
	PresentedTime time.Time
	SName         types.PrincipalName
	CTime         time.Time // This combines the ticket's CTime and Cusec
}

var replayCache ServiceCache

func GetReplayCache(d time.Duration) *ServiceCache {
	// Create a singleton of the ReplayCache and start a background thread to regularly clean out old entries
	var once sync.Once
	once.Do(func() {
		replayCache = make(ServiceCache)
		go func() {
			for {
				time.Sleep(d)
				replayCache.ClearOldEntries(d)
			}
		}()
	})
	return &replayCache
}

func (c *ServiceCache) AddEntry(sname types.PrincipalName, a types.Authenticator) {
	ct := a.CTime.Add(time.Duration(a.Cusec) * time.Microsecond)
	if ce, ok := (*c)[a.CName.GetPrincipalNameString()]; ok {
		ce.ReplayMap[ct] = ReplayCacheEntry{
			PresentedTime: time.Now().UTC(),
			SName:         sname,
			CTime:         ct,
		}
		ce.SeqNumber = a.SeqNumber
		ce.SubKey = a.SubKey
	} else {
		(*c)[a.CName.GetPrincipalNameString()] = ClientEntries{
			ReplayMap: map[time.Time]ReplayCacheEntry{
				ct: {
					PresentedTime: time.Now().UTC(),
					SName:         sname,
					CTime:         ct,
				},
			},
			SeqNumber: a.SeqNumber,
			SubKey:    a.SubKey,
		}
	}
}

func (c *ServiceCache) ClearOldEntries(d time.Duration) {
	for ck := range *c {
		for ct, e := range (*c)[ck].ReplayMap {
			if time.Now().UTC().Sub(e.PresentedTime) > d {
				delete((*c)[ck].ReplayMap, ct)
			}
		}
		if len((*c)[ck].ReplayMap) == 0 {
			delete((*c), ck)
		}
	}
}

func (c *ServiceCache) IsReplay(d time.Duration, sname types.PrincipalName, a types.Authenticator) bool {
	if ck, ok := (*c)[a.CName.GetPrincipalNameString()]; ok {
		ct := a.CTime.Add(time.Duration(a.Cusec) * time.Microsecond)
		if e, ok := ck.ReplayMap[ct]; ok {
			if e.SName.Equal(sname) {
				return true
			}
		}
	}
	c.AddEntry(sname, a)
	return false
}
