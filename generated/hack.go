package generated

import "sync"

type globalCallbackLocker struct {
	sync.Mutex
}

func (l *globalCallbackLocker) Lock() {
	l.Mutex.Lock()
	filNetReadCallbackEDA104B4Func = nil // enable its next reassignment in this lock
	filMerkleTreeProofCallback19BB3BC0Func = nil // enable its next reassignment in this lock
}

func (l *globalCallbackLocker) Unlock() {
	l.Mutex.Unlock()
}

// Global lock for C callback function.
var GlobalCallbackLocker globalCallbackLocker
