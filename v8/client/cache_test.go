package client

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
)

func TestCache_addEntry_getEntry_remove_clear(t *testing.T) {
	c := NewCache()
	cnt := 10
	var wg sync.WaitGroup
	for i := 0; i < cnt; i++ {
		wg.Add(1)
		tkt := messages.Ticket{
			SName: types.PrincipalName{
				NameType:   1,
				NameString: []string{fmt.Sprintf("%d", i), "test.cache"},
			},
		}
		key := types.EncryptionKey{
			KeyType:  1,
			KeyValue: []byte{byte(i)},
		}
		go func(i int) {
			e := c.addEntry(tkt, time.Unix(int64(0+i), 0), time.Unix(int64(10+i), 0), time.Unix(int64(20+i), 0), time.Unix(int64(30+i), 0), key)
			assert.Equal(t, fmt.Sprintf("%d/test.cache", i), e.SPN, "SPN cache key not as expected")
			wg.Done()
		}(i)
	}
	wg.Wait()
	for i := 0; i < cnt; i++ {
		wg.Add(1)
		go func(i int) {
			e, ok := c.getEntry(fmt.Sprintf("%d/test.cache", i))
			assert.True(t, ok, "cache entry %d was not found", i)
			assert.Equal(t, time.Unix(int64(0+i), 0), e.AuthTime, "auth time not as expected")
			assert.Equal(t, time.Unix(int64(10+i), 0), e.StartTime, "start time not as expected")
			assert.Equal(t, time.Unix(int64(20+i), 0), e.EndTime, "end time not as expected")
			assert.Equal(t, time.Unix(int64(30+i), 0), e.RenewTill, "renew time not as expected")
			assert.Equal(t, []string{fmt.Sprintf("%d", i), "test.cache"}, e.Ticket.SName.NameString, "ticket not correct")
			assert.Equal(t, []byte{byte(i)}, e.SessionKey.KeyValue, "session key not correct")
			wg.Done()
		}(i)
	}
	wg.Wait()
	_, ok := c.getEntry(fmt.Sprintf("%d/test.cache", cnt+1))
	assert.False(t, ok, "entry found in cache when it shouldn't have been")

	// Remove just the even entries
	for i := 0; i < cnt; i += 2 {
		wg.Add(1)
		go func(i int) {
			c.RemoveEntry(fmt.Sprintf("%d/test.cache", i))
			wg.Done()
		}(i)
	}
	wg.Wait()

	for i := 0; i < cnt; i++ {
		wg.Add(1)
		go func(i int) {
			if i%2 == 0 {
				_, ok := c.getEntry(fmt.Sprintf("%d/test.cache", cnt+1))
				assert.False(t, ok, "entry %d found in cache when it shouldn't have been", i)
			} else {
				e, ok := c.getEntry(fmt.Sprintf("%d/test.cache", i))
				assert.True(t, ok, "cache entry %d was not found", i)
				assert.Equal(t, time.Unix(int64(0+i), 0), e.AuthTime, "auth time not as expected")
				assert.Equal(t, time.Unix(int64(10+i), 0), e.StartTime, "start time not as expected")
				assert.Equal(t, time.Unix(int64(20+i), 0), e.EndTime, "end time not as expected")
				assert.Equal(t, time.Unix(int64(30+i), 0), e.RenewTill, "renew time not as expected")
				assert.Equal(t, []string{fmt.Sprintf("%d", i), "test.cache"}, e.Ticket.SName.NameString, "ticket not correct")
				assert.Equal(t, []byte{byte(i)}, e.SessionKey.KeyValue, "session key not correct")
			}
			wg.Done()
		}(i)
	}
	wg.Wait()

	// Clear the cache
	c.clear()
	for i := 0; i < cnt; i++ {
		wg.Add(1)
		go func(i int) {
			_, ok := c.getEntry(fmt.Sprintf("%d/test.cache", cnt+1))
			assert.False(t, ok, "entry %d found in cache when it shouldn't have been", i)
			wg.Done()
		}(i)
	}
	wg.Wait()
}

func TestCache_JSON(t *testing.T) {
	c := NewCache()
	cnt := 3
	for i := 0; i < cnt; i++ {
		tkt := messages.Ticket{
			SName: types.PrincipalName{
				NameType:   1,
				NameString: []string{fmt.Sprintf("%d", i), "test.cache"},
			},
		}
		key := types.EncryptionKey{
			KeyType:  1,
			KeyValue: []byte{byte(i)},
		}
		e := c.addEntry(tkt, time.Unix(int64(0+i), 0), time.Unix(int64(10+i), 0), time.Unix(int64(20+i), 0), time.Unix(int64(30+i), 0), key)
		assert.Equal(t, fmt.Sprintf("%d/test.cache", i), e.SPN, "SPN cache key not as expected")
	}
	expected := `[
  {
    "SPN": "0/test.cache",
    "AuthTime": "1970-01-01T01:00:00+01:00",
    "StartTime": "1970-01-01T01:00:10+01:00",
    "EndTime": "1970-01-01T01:00:20+01:00",
    "RenewTill": "1970-01-01T01:00:30+01:00"
  },
  {
    "SPN": "1/test.cache",
    "AuthTime": "1970-01-01T01:00:01+01:00",
    "StartTime": "1970-01-01T01:00:11+01:00",
    "EndTime": "1970-01-01T01:00:21+01:00",
    "RenewTill": "1970-01-01T01:00:31+01:00"
  },
  {
    "SPN": "2/test.cache",
    "AuthTime": "1970-01-01T01:00:02+01:00",
    "StartTime": "1970-01-01T01:00:12+01:00",
    "EndTime": "1970-01-01T01:00:22+01:00",
    "RenewTill": "1970-01-01T01:00:32+01:00"
  }
]`
	j, err := c.JSON()
	if err != nil {
		t.Errorf("error getting json output of cache: %v", err)
	}
	assert.Equal(t, expected, j, "json output not as expected")
}
