package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang program ./bpf/program.bpf.c

func do() error {
	spec, err := loadProgram()
	if err != nil {
		return err
	}

	var objs programObjects
	opts := ebpf.CollectionOptions{}

	if err := spec.LoadAndAssign(&objs, &opts); err != nil {
		return err
	}
	defer objs.Close()

	l, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.OpenTracepoint, nil)
	if err != nil {
		return err
	}
	defer l.Close()

	// Graceful shutdown
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)
	<-exit

	return nil
}

func main() {
	err := do()
	if err != nil {
		fmt.Printf("failed to do: %s\n", err)
	}
}
