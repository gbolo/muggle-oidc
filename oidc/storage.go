package oidc

import (
	"fmt"
	"sync"
)

// An opaque value used by the client to maintain state between the request and callback.
// Therefore, we should keep track of the state parameter when we generate our auth request
// then validate that the corresponding browser agent returned the same state during the callback.
type state string

// This is what we use to keep track of browser agents. We will set/store this as a cookie when
// returning the 302 (auth request) during the first part of the flow.
type browserSessionID string

type memoryStore struct {
	sessionStore map[browserSessionID]map[state]bool
	sync.RWMutex
}

// this is our instance of memoryStore for state validation
var StateStore memoryStore

func init() {
	StateStore = memoryStore{sessionStore: make(map[browserSessionID]map[state]bool)}
}

func (s *memoryStore) AddState(bid string, st string) (err error) {
	s.Lock()
	defer s.Unlock()
	if states, browserSessionExists := s.sessionStore[browserSessionID(bid)]; browserSessionExists {
		if _, stateExists := states[state(st)]; stateExists {
			err = fmt.Errorf("this state (%s) is already present for session ID %s", st, bid)
		} else {
			states[state(st)] = false
		}
	} else {
		log.Debugf("adding new state %s for browser session id %s", st, bid)
		s.sessionStore[browserSessionID(bid)] = map[state]bool{state(st): false}
	}
	return
}

func (s *memoryStore) ValidateState(bid string, st string) (valid bool) {
	s.Lock()
	defer s.Unlock()
	if states, browserSessionExists := s.sessionStore[browserSessionID(bid)]; browserSessionExists {
		if _, stateExists := states[state(st)]; stateExists {
			s.sessionStore[browserSessionID(bid)][state(st)] = true
			valid = true
		}
	}
	return
}
