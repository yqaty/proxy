package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
)

const bufferSize = 1 << 12

func relay(reader *bufio.Reader, writer *bufio.Writer, wg *sync.WaitGroup) {
	defer wg.Done()
	data := make([]byte, bufferSize)
	for {
		n, err := reader.Read(data)
		if err != nil {
			return
		}
		_, err = writer.Write(data[:n])
		if err != nil {
			return
		}
		err = writer.Flush()
		if err != nil {
			return
		}
	}
}

func dealRequest(reader *bufio.Reader, writer *bufio.Writer) error {
	ver, err := reader.ReadByte()
	if err != nil {
		return err
	}
	if ver != 0x05 {
		return errors.New("unexpected protocol")
	}
	cmd, err := reader.ReadByte()
	if err != nil {
		return err
	}
	if cmd == 0x00 || cmd > 0x03 {
		return errors.New("unexpected command")
	}
	_, err = reader.Discard(1)
	if err != nil {
		return err
	}
	atyp, err := reader.ReadByte()
	if err != nil {
		return err
	}
	if reader.Buffered() <= 2 {
		return errors.New("unexpected message")
	}
	var ip net.IP
	if atyp == 0x01 || atyp == 0x04 {
		addr := make([]byte, atyp*4)
		_, err := io.ReadFull(reader, addr)
		if err != nil {
			return err
		}
		ip = net.IP(addr)
	} else if atyp == 0x03 {
		len, err := reader.ReadByte()
		if err != nil {
			return err
		}
		addr := make([]byte, len)
		_, err = io.ReadFull(reader, addr)
		if err != nil {
			return err
		}
		ipAddr, err := net.ResolveIPAddr("ip", string(addr))
		if err != nil {
			return err
		}
		ip = ipAddr.IP
	} else {
		return errors.New("invaild atyp")
	}
	sport := make([]byte, 2)
	_, err = io.ReadFull(reader, sport)
	if err != nil {
		return err
	}
	port := binary.BigEndian.Uint16(sport)
	conn, err := net.Dial("tcp", ip.String()+":"+strconv.Itoa(int(port)))
	if err != nil {
		return err
	}
	defer conn.Close()
	localaddr := conn.LocalAddr().(*net.TCPAddr)
	writer.Write([]byte{0x05, 0x00, 0x00, 0x01})
	writer.Write([]byte(localaddr.IP))
	ports := make([]byte, 2)
	binary.BigEndian.PutUint16(ports, uint16(localaddr.Port))
	writer.Write(ports)
	writer.Flush()
	wg := new(sync.WaitGroup)
	wg.Add(2)
	go relay(reader, bufio.NewWriter(conn), wg)
	go relay(bufio.NewReader(conn), writer, wg)
	wg.Wait()
	return nil
}

func Serve(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReaderSize(conn, bufferSize)
	writer := bufio.NewWriterSize(conn, bufferSize)
	err := dealRequest(reader, writer)
	fmt.Println(err)
}

func Run() {
	listener, err := net.Listen("tcp", "127.0.0.1:10010")
	if err != nil {
		log.Fatal(err)
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go Serve(conn)
	}
}

func main() {
	Run()
}
