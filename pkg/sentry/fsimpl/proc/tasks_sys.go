// Copyright 2019 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proc

import (
	"bytes"
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/usermem"
)

// +stateify savable
type tcpMemDir int

const (
	tcpRMem tcpMemDir = iota
	tcpWMem
)

// newSysDir returns the dentry corresponding to /proc/sys directory.
func (fs *filesystem) newSysDir(root *auth.Credentials, k *kernel.Kernel) kernfs.Inode {
	return fs.newStaticDir(root, map[string]kernfs.Inode{
		"kernel": fs.newStaticDir(root, map[string]kernfs.Inode{
			"hostname": fs.newInode(root, 0444, &hostnameData{}),
			"shmall":   fs.newInode(root, 0444, shmData(linux.SHMALL)),
			"shmmax":   fs.newInode(root, 0444, shmData(linux.SHMMAX)),
			"shmmni":   fs.newInode(root, 0444, shmData(linux.SHMMNI)),
		}),
		"vm": fs.newStaticDir(root, map[string]kernfs.Inode{
			"mmap_min_addr":     fs.newInode(root, 0444, &mmapMinAddrData{k: k}),
			"overcommit_memory": fs.newInode(root, 0444, newStaticFile("0\n")),
		}),
		"net": fs.newSysNetDir(root, k),
	})
}

// newSysNetDir returns the dentry corresponding to /proc/sys/net directory.
func (fs *filesystem) newSysNetDir(root *auth.Credentials, k *kernel.Kernel) kernfs.Inode {
	var contents map[string]kernfs.Inode

	// TODO(gvisor.dev/issue/1833): Support for using the network stack in the
	// network namespace of the calling process.
	if stack := k.RootNetworkNamespace().Stack(); stack != nil {
		contents = map[string]kernfs.Inode{
			"ipv4": fs.newStaticDir(root, map[string]kernfs.Inode{
				"tcp_recovery": fs.newInode(root, 0644, &tcpRecoveryData{stack: stack}),
				"tcp_rmem":     fs.newInode(root, 0644, &tcpMemData{stack: stack, dir: tcpRMem}),
				"tcp_sack":     fs.newInode(root, 0644, &tcpSackData{stack: stack}),
				"tcp_wmem":     fs.newInode(root, 0644, &tcpMemData{stack: stack, dir: tcpWMem}),
				"ip_forward":   fs.newInode(root, 0444, &ipForwarding{stack: stack}),

				// The following files are simple stubs until they are implemented in
				// netstack, most of these files are configuration related. We use the
				// value closest to the actual netstack behavior or any empty file, all
				// of these files will have mode 0444 (read-only for all users).
				"ip_local_port_range":     fs.newInode(root, 0444, newStaticFile("16000   65535")),
				"ip_local_reserved_ports": fs.newInode(root, 0444, newStaticFile("")),
				"ipfrag_time":             fs.newInode(root, 0444, newStaticFile("30")),
				"ip_nonlocal_bind":        fs.newInode(root, 0444, newStaticFile("0")),
				"ip_no_pmtu_disc":         fs.newInode(root, 0444, newStaticFile("1")),

				// tcp_allowed_congestion_control tell the user what they are able to
				// do as an unprivledged process so we leave it empty.
				"tcp_allowed_congestion_control":   fs.newInode(root, 0444, newStaticFile("")),
				"tcp_available_congestion_control": fs.newInode(root, 0444, newStaticFile("reno")),
				"tcp_congestion_control":           fs.newInode(root, 0444, newStaticFile("reno")),

				// Many of the following stub files are features netstack doesn't
				// support. The unsupported features return "0" to indicate they are
				// disabled.
				"tcp_base_mss":              fs.newInode(root, 0444, newStaticFile("1280")),
				"tcp_dsack":                 fs.newInode(root, 0444, newStaticFile("0")),
				"tcp_early_retrans":         fs.newInode(root, 0444, newStaticFile("0")),
				"tcp_fack":                  fs.newInode(root, 0444, newStaticFile("0")),
				"tcp_fastopen":              fs.newInode(root, 0444, newStaticFile("0")),
				"tcp_fastopen_key":          fs.newInode(root, 0444, newStaticFile("")),
				"tcp_invalid_ratelimit":     fs.newInode(root, 0444, newStaticFile("0")),
				"tcp_keepalive_intvl":       fs.newInode(root, 0444, newStaticFile("0")),
				"tcp_keepalive_probes":      fs.newInode(root, 0444, newStaticFile("0")),
				"tcp_keepalive_time":        fs.newInode(root, 0444, newStaticFile("7200")),
				"tcp_mtu_probing":           fs.newInode(root, 0444, newStaticFile("0")),
				"tcp_no_metrics_save":       fs.newInode(root, 0444, newStaticFile("1")),
				"tcp_probe_interval":        fs.newInode(root, 0444, newStaticFile("0")),
				"tcp_probe_threshold":       fs.newInode(root, 0444, newStaticFile("0")),
				"tcp_retries1":              fs.newInode(root, 0444, newStaticFile("3")),
				"tcp_retries2":              fs.newInode(root, 0444, newStaticFile("15")),
				"tcp_rfc1337":               fs.newInode(root, 0444, newStaticFile("1")),
				"tcp_slow_start_after_idle": fs.newInode(root, 0444, newStaticFile("1")),
				"tcp_synack_retries":        fs.newInode(root, 0444, newStaticFile("5")),
				"tcp_syn_retries":           fs.newInode(root, 0444, newStaticFile("3")),
				"tcp_timestamps":            fs.newInode(root, 0444, newStaticFile("1")),
			}),
			"core": fs.newStaticDir(root, map[string]kernfs.Inode{
				"default_qdisc": fs.newInode(root, 0444, newStaticFile("pfifo_fast")),
				"message_burst": fs.newInode(root, 0444, newStaticFile("10")),
				"message_cost":  fs.newInode(root, 0444, newStaticFile("5")),
				"optmem_max":    fs.newInode(root, 0444, newStaticFile("0")),
				"rmem_default":  fs.newInode(root, 0444, newStaticFile("212992")),
				"rmem_max":      fs.newInode(root, 0444, newStaticFile("212992")),
				"somaxconn":     fs.newInode(root, 0444, newStaticFile("128")),
				"wmem_default":  fs.newInode(root, 0444, newStaticFile("212992")),
				"wmem_max":      fs.newInode(root, 0444, newStaticFile("212992")),
			}),
		}
	}

	return fs.newStaticDir(root, contents)
}

// mmapMinAddrData implements vfs.DynamicBytesSource for
// /proc/sys/vm/mmap_min_addr.
//
// +stateify savable
type mmapMinAddrData struct {
	kernfs.DynamicBytesFile

	k *kernel.Kernel
}

var _ dynamicInode = (*mmapMinAddrData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *mmapMinAddrData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	fmt.Fprintf(buf, "%d\n", d.k.Platform.MinUserAddress())
	return nil
}

// hostnameData implements vfs.DynamicBytesSource for /proc/sys/kernel/hostname.
//
// +stateify savable
type hostnameData struct {
	kernfs.DynamicBytesFile
}

var _ dynamicInode = (*hostnameData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (*hostnameData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	utsns := kernel.UTSNamespaceFromContext(ctx)
	buf.WriteString(utsns.HostName())
	buf.WriteString("\n")
	return nil
}

// tcpSackData implements vfs.WritableDynamicBytesSource for
// /proc/sys/net/tcp_sack.
//
// +stateify savable
type tcpSackData struct {
	kernfs.DynamicBytesFile

	stack   inet.Stack `state:"wait"`
	enabled *bool
}

var _ vfs.WritableDynamicBytesSource = (*tcpSackData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *tcpSackData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	if d.enabled == nil {
		sack, err := d.stack.TCPSACKEnabled()
		if err != nil {
			return err
		}
		d.enabled = &sack
	}

	val := "0\n"
	if *d.enabled {
		// Technically, this is not quite compatible with Linux. Linux stores these
		// as an integer, so if you write "2" into tcp_sack, you should get 2 back.
		// Tough luck.
		val = "1\n"
	}
	_, err := buf.WriteString(val)
	return err
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (d *tcpSackData) Write(ctx context.Context, src usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		// No need to handle partial writes thus far.
		return 0, syserror.EINVAL
	}
	if src.NumBytes() == 0 {
		return 0, nil
	}

	// Limit the amount of memory allocated.
	src = src.TakeFirst(usermem.PageSize - 1)

	var v int32
	n, err := usermem.CopyInt32StringInVec(ctx, src.IO, src.Addrs, &v, src.Opts)
	if err != nil {
		return 0, err
	}
	if d.enabled == nil {
		d.enabled = new(bool)
	}
	*d.enabled = v != 0
	return n, d.stack.SetTCPSACKEnabled(*d.enabled)
}

// tcpRecoveryData implements vfs.WritableDynamicBytesSource for
// /proc/sys/net/ipv4/tcp_recovery.
//
// +stateify savable
type tcpRecoveryData struct {
	kernfs.DynamicBytesFile

	stack inet.Stack `state:"wait"`
}

var _ vfs.WritableDynamicBytesSource = (*tcpRecoveryData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *tcpRecoveryData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	recovery, err := d.stack.TCPRecovery()
	if err != nil {
		return err
	}

	_, err = buf.WriteString(fmt.Sprintf("%d\n", recovery))
	return err
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (d *tcpRecoveryData) Write(ctx context.Context, src usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		// No need to handle partial writes thus far.
		return 0, syserror.EINVAL
	}
	if src.NumBytes() == 0 {
		return 0, nil
	}

	// Limit the amount of memory allocated.
	src = src.TakeFirst(usermem.PageSize - 1)

	var v int32
	n, err := usermem.CopyInt32StringInVec(ctx, src.IO, src.Addrs, &v, src.Opts)
	if err != nil {
		return 0, err
	}
	if err := d.stack.SetTCPRecovery(inet.TCPLossRecovery(v)); err != nil {
		return 0, err
	}
	return n, nil
}

// tcpMemData implements vfs.WritableDynamicBytesSource for
// /proc/sys/net/ipv4/tcp_rmem and /proc/sys/net/ipv4/tcp_wmem.
//
// +stateify savable
type tcpMemData struct {
	kernfs.DynamicBytesFile

	dir   tcpMemDir
	stack inet.Stack `state:"wait"`

	// mu protects against concurrent reads/writes to FDs based on the dentry
	// backing this byte source.
	mu sync.Mutex `state:"nosave"`
}

var _ vfs.WritableDynamicBytesSource = (*tcpMemData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *tcpMemData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	size, err := d.readSizeLocked()
	if err != nil {
		return err
	}
	_, err = buf.WriteString(fmt.Sprintf("%d\t%d\t%d\n", size.Min, size.Default, size.Max))
	return err
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (d *tcpMemData) Write(ctx context.Context, src usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		// No need to handle partial writes thus far.
		return 0, syserror.EINVAL
	}
	if src.NumBytes() == 0 {
		return 0, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	// Limit the amount of memory allocated.
	src = src.TakeFirst(usermem.PageSize - 1)
	size, err := d.readSizeLocked()
	if err != nil {
		return 0, err
	}
	buf := []int32{int32(size.Min), int32(size.Default), int32(size.Max)}
	n, err := usermem.CopyInt32StringsInVec(ctx, src.IO, src.Addrs, buf, src.Opts)
	if err != nil {
		return 0, err
	}
	newSize := inet.TCPBufferSize{
		Min:     int(buf[0]),
		Default: int(buf[1]),
		Max:     int(buf[2]),
	}
	if err := d.writeSizeLocked(newSize); err != nil {
		return 0, err
	}
	return n, nil
}

// Precondition: d.mu must be locked.
func (d *tcpMemData) readSizeLocked() (inet.TCPBufferSize, error) {
	switch d.dir {
	case tcpRMem:
		return d.stack.TCPReceiveBufferSize()
	case tcpWMem:
		return d.stack.TCPSendBufferSize()
	default:
		panic(fmt.Sprintf("unknown tcpMemFile type: %v", d.dir))
	}
}

// Precondition: d.mu must be locked.
func (d *tcpMemData) writeSizeLocked(size inet.TCPBufferSize) error {
	switch d.dir {
	case tcpRMem:
		return d.stack.SetTCPReceiveBufferSize(size)
	case tcpWMem:
		return d.stack.SetTCPSendBufferSize(size)
	default:
		panic(fmt.Sprintf("unknown tcpMemFile type: %v", d.dir))
	}
}

// ipForwarding implements vfs.WritableDynamicBytesSource for
// /proc/sys/net/ipv4/ip_forwarding.
//
// +stateify savable
type ipForwarding struct {
	kernfs.DynamicBytesFile

	stack   inet.Stack `state:"wait"`
	enabled *bool
}

var _ vfs.WritableDynamicBytesSource = (*ipForwarding)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (ipf *ipForwarding) Generate(ctx context.Context, buf *bytes.Buffer) error {
	if ipf.enabled == nil {
		enabled := ipf.stack.Forwarding(ipv4.ProtocolNumber)
		ipf.enabled = &enabled
	}

	val := "0\n"
	if *ipf.enabled {
		// Technically, this is not quite compatible with Linux. Linux stores these
		// as an integer, so if you write "2" into tcp_sack, you should get 2 back.
		// Tough luck.
		val = "1\n"
	}
	buf.WriteString(val)

	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (ipf *ipForwarding) Write(ctx context.Context, src usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		// No need to handle partial writes thus far.
		return 0, syserror.EINVAL
	}
	if src.NumBytes() == 0 {
		return 0, nil
	}

	// Limit input size so as not to impact performance if input size is large.
	src = src.TakeFirst(usermem.PageSize - 1)

	var v int32
	n, err := usermem.CopyInt32StringInVec(ctx, src.IO, src.Addrs, &v, src.Opts)
	if err != nil {
		return 0, err
	}
	if ipf.enabled == nil {
		ipf.enabled = new(bool)
	}
	*ipf.enabled = v != 0
	if err := ipf.stack.SetForwarding(ipv4.ProtocolNumber, *ipf.enabled); err != nil {
		return 0, err
	}
	return n, nil
}
