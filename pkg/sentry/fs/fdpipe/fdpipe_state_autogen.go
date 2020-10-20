// automatically generated by stateify.

package fdpipe

import (
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/state"
)

func (p *pipeOperations) StateTypeName() string {
	return "pkg/sentry/fs/fdpipe.pipeOperations"
}

func (p *pipeOperations) StateFields() []string {
	return []string{
		"flags",
		"opener",
		"readAheadBuffer",
	}
}

func (p *pipeOperations) StateSave(stateSinkObject state.Sink) {
	p.beforeSave()
	var flagsValue fs.FileFlags = p.saveFlags()
	stateSinkObject.SaveValue(0, flagsValue)
	stateSinkObject.Save(1, &p.opener)
	stateSinkObject.Save(2, &p.readAheadBuffer)
}

func (p *pipeOperations) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.LoadWait(1, &p.opener)
	stateSourceObject.Load(2, &p.readAheadBuffer)
	stateSourceObject.LoadValue(0, new(fs.FileFlags), func(y interface{}) { p.loadFlags(y.(fs.FileFlags)) })
	stateSourceObject.AfterLoad(p.afterLoad)
}

func init() {
	state.Register((*pipeOperations)(nil))
}
