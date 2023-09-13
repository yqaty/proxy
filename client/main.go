package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
)

const (
	serverIP = "127.0.0.1"
	//serverIP   = "60.204.203.164"
	serverPort = "10010"
	bufferSize = 1 << 12
)

func authentication(reader *bufio.Reader, writer *bufio.Writer) error {
	ver, err := reader.ReadByte()
	if err != nil {
		return err
	}
	if ver != 0x05 {
		return errors.New("unexpected protocol")
	}
	mnum, err := reader.ReadByte()
	if err != nil {
		return err
	}
	methods := make([]byte, mnum)
	_, err = io.ReadFull(reader, methods)
	if err != nil {
		return err
	}
	for _, v := range methods {
		if v == 0x00 {
			writer.Write([]byte{0x05, 0x00})
			writer.Flush()
			return nil
		}
	}
	writer.Write([]byte{0x05, 0x01})
	return errors.New("unexpected methods")
}

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

func connectRelayServer(reader *bufio.Reader, writer *bufio.Writer) error {
	conn, err := net.Dial("tcp", serverIP+":"+serverPort)
	if err != nil {
		fmt.Println(err)
		return err
	}
	defer conn.Close()
	data := make([]byte, bufferSize)
	n, err := reader.Read(data)
	if err != nil {
		return err
	}
	conn.Write(data[:n])
	n, err = conn.Read(data)
	if err != nil {
		return err
	}
	_, err = writer.Write(data[:n])
	if err != nil {
		return err
	}
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
	err := authentication(reader, writer)
	if err != nil {
		conn.Close()
		return
	}
	err = connectRelayServer(reader, writer)
	fmt.Println(err)
}

func Run() {
	client, err := net.Listen("tcp", ":9090")
	if err != nil {
		log.Println(err)
		return
	}
	for {
		conn, err := client.Accept()
		if err != nil {
			log.Println(err)
		}
		go Serve(conn)
	}
}

func main() {
	Run()
}
