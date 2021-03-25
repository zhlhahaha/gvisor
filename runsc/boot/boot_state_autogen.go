// automatically generated by stateify.

package boot

import (
	"gvisor.dev/gvisor/pkg/state"
)

func (f *sandboxNetstackCreator) StateTypeName() string {
	return "runsc/boot.sandboxNetstackCreator"
}

func (f *sandboxNetstackCreator) StateFields() []string {
	return []string{
		"clock",
		"uniqueID",
	}
}

func (f *sandboxNetstackCreator) beforeSave() {}

// +checklocksignore
func (f *sandboxNetstackCreator) StateSave(stateSinkObject state.Sink) {
	f.beforeSave()
	stateSinkObject.Save(0, &f.clock)
	stateSinkObject.Save(1, &f.uniqueID)
}

func (f *sandboxNetstackCreator) afterLoad() {}

// +checklocksignore
func (f *sandboxNetstackCreator) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &f.clock)
	stateSourceObject.Load(1, &f.uniqueID)
}

func init() {
	state.Register((*sandboxNetstackCreator)(nil))
}
