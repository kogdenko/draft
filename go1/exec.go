package main

import (
	"bytes"
	//	"fmt"
	"log"
	"os/exec"
	//	"strings"
	"time"
)

func main() {
	var out bytes.Buffer
	cmd := exec.Command("/usr/sbin/nginx", "-c", "/home/k.kogdenko/Projects/gbtcp/test/nginx.conf")
	cmd.Stdout = &out
	err := cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("ok %d", cmd.Process.Pid)
	cmd.Process.Kill()
	cmd.Wait()
	for {
		time.Sleep(1)
	}
}
