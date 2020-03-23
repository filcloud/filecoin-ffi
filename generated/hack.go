package generated

import "sync"

type globalCallbackLocker struct {
	sync.Mutex
}

func (l *globalCallbackLocker) Lock() {
	l.Mutex.Lock()
	if l == &GlobalWinningPoStCallbackLocker {
		filWinningMerkleTreeProofCallback26929706Func = nil // enable its next reassignment in this lock
	} else {
		filWindowMerkleTreeProofCallback9C3E2DBCFunc = nil // enable its next reassignment in this lock
	}
}

func (l *globalCallbackLocker) Unlock() {
	l.Mutex.Unlock()
}

// Global lock for C callback function.
var GlobalWinningPoStCallbackLocker globalCallbackLocker
var GlobalWindowPoStCallbackLocker globalCallbackLocker
