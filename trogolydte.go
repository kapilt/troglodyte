// A small SSH daemon providing bash sessions into containers
//
// docker run -t -i ubuntu:14.04 sleep 10000

// Server:
// cd my/new/dir/
// #generate server keypair
// ssh-keygen -t rsa
// go get -v .
// go run sshd.go
//
// Client:
// ssh foo@localhost -p 2200 #pass=bar

package main

import (
	"encoding/binary"
	"fmt"
//	"io"
	"io/ioutil"
	"log"
	"net"
//	"os/exec"
//	"sync"
	"syscall"
	"unsafe"
	"os"
	"time"

//	"github.com/kr/pty"
	"golang.org/x/crypto/ssh"
	"github.com/fsouza/go-dockerclient"
)


func main() {

	// In the latest version of crypto/ssh (after Go 1.3), the SSH server type has been removed
	// in favour of an SSH connection type. A ssh.ServerConn is created by passing an existing
	// net.Conn and a ssh.ServerConfig to ssh.NewServerConn, in effect, upgrading the net.Conn
	// into an ssh.ServerConn

	config := &ssh.ServerConfig{
		PasswordCallback: passwordAuth,
		PublicKeyCallback: keyAuth,
	}

	// You can generate a keypair with 'ssh-keygen -t rsa'
	privateBytes, err := ioutil.ReadFile("id_rsa")
	if err != nil {
		log.Fatal("Failed to load private key (./id_rsa)")
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key")
	}

	config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be accepted.
	listener, err := net.Listen("tcp", "0.0.0.0:2200")
	if err != nil {
		log.Fatalf("Failed to listen on 2200 (%s)", err)
	}

	// Accept all connections
	log.Print("Listening on 2200...")
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming connection (%s)", err)
			continue
		}
		// Before use, a handshake must be performed on the incoming net.Conn.
		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, config)
		if err != nil {
			log.Printf("Failed to handshake (%s)", err)
			continue
		}

		log.Printf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
		// Discard all global out-of-band Requests
		go ssh.DiscardRequests(reqs)
		// Accept all channels
		go handleChannels(chans)
	}
}



func keyAuth(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	log.Println(conn.RemoteAddr(), "authenticate with", key.Type())
	return nil, nil
}

func passwordAuth(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	// Should use constant-time compare (or better, salt+hash) in a production setting.
	if c.User() == "foo" && string(pass) == "bar" {
		return nil, nil
	}
	return nil, fmt.Errorf("password rejected for %q", c.User())
}

func handleChannels(chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel in go routine
	for newChannel := range chans {
		go handleChannel(newChannel)
	}
}

func handleChannel(newChannel ssh.NewChannel) {
	// Since we're handling a shell, we expect a
	// channel type of "session". The also describes
	// "x11", "direct-tcpip" and "forwarded-tcpip"
	// channel types.
	if t := newChannel.ChannelType(); t != "session" {
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		return
	}

	// At this point, we have the opportunity to reject the client's
	// request for another logical connection
	connection, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept channel (%s)", err)
		return
	}

	// Fire up bash for this session
	// bash := exec.Command("bash")

	endpoint := "unix:///var/run/docker.sock"
	client, _ := docker.NewClient(endpoint)
	execConfig := docker.CreateExecOptions{
		Container: "606",
		AttachStdin: true,
		AttachStdout: true,
		AttachStderr: true,
		Tty: true,
		Cmd: []string{"/bin/bash"},
	}

	execObj, err := client.CreateExec(execConfig)
	if err != nil {
		fmt.Printf("\nUnknown error %s\n", err)
		os.Exit(1)	
	}

	fmt.Printf("Exec Obj %s\n", execObj.ID)
	success := make(chan struct{})

	startExecConfig := docker.StartExecOptions{
		Detach: false,
		InputStream: connection,
		OutputStream: connection,
		ErrorStream: connection,
		Tty: true,
		RawTerminal: true,
		Success: success,
	}

	// Prepare teardown function
	close := func() {
		connection.Close()
/*		_, err := bash.Process.Wait()
		if err != nil {
			log.Printf("Failed to exit bash (%s)", err)
		} */
		log.Printf("Session closed")
	}

	// Startup the execution
	go func() {
		if err := client.StartExec(execObj.ID, startExecConfig); err != nil {
			fmt.Errorf("unknown error %v %s", err, err)
			close()
		}
	}()


	// Strange little dance the docker client wants to stream
	<- success
	success <- struct{}{}	

	// Start a poller to know when we're done
	go func() {
		var e *docker.ExecInspect
		var err error
		for {
			log.Printf("Checking if process done")
			e, err = client.InspectExec(execObj.ID)
			if err != nil {
				close() 
			}
			if e.Running == false {
				close()
			}
			time.Sleep(time.Duration(2) * time.Second)

		}
	}()

	/* Allocate a terminal for this channel
	log.Print("Creating pty...")
	bashf, err := pty.Start(bash)
	if err != nil {
		log.Printf("Could not start pty (%s)", err)
		close()
		return
	} */

	//pipe session to bash and visa-versa
	/*
	var once sync.Once
	go func() {
		io.Copy(connection, bashf)
		once.Do(close)
	}()
	go func() {
		io.Copy(bashf, connection)
		once.Do(close)
	}()
        */

	// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
	go func() {
		for req := range requests {
			switch req.Type {
			case "shell":
				// We only accept the default shell
				// (i.e. no command in the Payload)
				if len(req.Payload) == 0 {
					req.Reply(true, nil)
				}
			case "pty-req":
				termLen := req.Payload[3]
				w, h := parseDims(req.Payload[termLen+4:])
				client.ResizeExecTTY(execObj.ID, int(w), int(h))

				// SetWinsize(bashf.Fd(), w, h)
				// Responding true (OK) here will let the client
				// know we have a pty ready for input
				req.Reply(true, nil)
			case "window-change":
				w, h := parseDims(req.Payload)
				client.ResizeExecTTY(execObj.ID, int(w), int(h))
				// SetWinsize(bashf.Fd(), w, h)
			}
		}
	}()
}

// =======================

// parseDims extracts terminal dimensions (width x height) from the provided buffer.
func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}

// ======================

// Winsize stores the Height and Width of a terminal.
type Winsize struct {
	Height uint16
	Width  uint16
	x      uint16 // unused
	y      uint16 // unused
}

// SetWinsize sets the size of the given pty.
func SetWinsize(fd uintptr, w, h uint32) {
	ws := &Winsize{Width: uint16(w), Height: uint16(h)}
	syscall.Syscall(
		syscall.SYS_IOCTL, fd, 
		uintptr(syscall.TIOCSWINSZ), 
		uintptr(unsafe.Pointer(ws)))
}

// Borrowed from https://github.com/creack/termios/blob/master/win/win.go
