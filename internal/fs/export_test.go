package fs

// CheckFilename is exported for testing from fs_test.
var CheckFilename = checkFilename

var TestHookAfterReadDirBatch *func()
var TestHookBeforeOpenDir *func(childName string)

func init() {
	TestHookAfterReadDirBatch = &testHookAfterReadDirBatch
	TestHookBeforeOpenDir = &testHookBeforeOpenDir
}
