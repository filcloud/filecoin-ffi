package generated

import "sync"

type netReadCallbackLocker struct {
	sync.Mutex
}

func (l *netReadCallbackLocker) Lock() {
	l.Mutex.Lock()
	filNetReadCallbackEDA104B4Func = nil // enable its next reassignment in this lock
}

func (l *netReadCallbackLocker) Unlock() {
	l.Mutex.Unlock()
}

// Global lock for C function of FilNetReadCallback.
var NetReadCallbackLocker netReadCallbackLocker
