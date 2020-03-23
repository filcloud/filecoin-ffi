package generated

import "sync"

type globalCallbackLocker struct {
	sync.Mutex
}

func (l *globalCallbackLocker) Lock() {
	l.Mutex.Lock()
}

func (l *globalCallbackLocker) Unlock() {
	l.Mutex.Unlock()
}

// Global lock for C callback function.
var GlobalWinningPoStCallbackLocker globalCallbackLocker
var GlobalWindowPoStCallbackLocker globalCallbackLocker
