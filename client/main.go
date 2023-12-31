package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/viper"
)

var key, serverIP, serverPort, listenPort, userName, password string
var global bool

const (
	bufferSize = 1 << 12
)

func ReadConfig() {
	viper.SetConfigName("config")
	viper.SetConfigType("json")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("%w", err))
	}
	key = viper.GetString("key")
	serverIP = viper.GetString("server_ip")
	serverPort = viper.GetString("server_port")
	listenPort = viper.GetString("listen_port")
	userName = viper.GetString("user_name")
	password = viper.GetString("password")
	global = viper.GetBool("global")
}

func Pad(buf []byte, n int, size int) ([]byte, error) {
	padLen := size - n%size
	for i := 0; i < padLen; i++ {
		buf[n+i] = byte(padLen)
	}
	return buf[:n+padLen], nil
}

func Unpad(padded []byte, size int) ([]byte, error) {
	if len(padded)%size != 0 {
		return nil, errors.New("pkcs7: padded value wasn't in correct size")
	}
	bufLen := len(padded) - int(padded[len(padded)-1])
	return padded[:bufLen], nil
}

func EncryptAES(key []byte, plainText []byte, n int) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := plainText[n : n+16]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(plainText[:n], plainText[:n])
	return plainText[:n+16], err
}

func DecryptAES(key []byte, cipherText []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	n := len(cipherText)
	if n < aes.BlockSize {
		err = errors.New("ciphertext block size is too short")
		return nil, err
	}
	iv := cipherText[n-aes.BlockSize:]
	cipherText = cipherText[:n-aes.BlockSize]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)
	return cipherText, err
}

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

func encodeSend(writer *bufio.Writer, data []byte, n int) error {
	data2, err := Pad(data, n, 16)
	if err != nil {
		return err
	}
	data2, err = EncryptAES([]byte(key), data, len(data2))
	if err != nil {
		return err
	}
	l := make([]byte, 2)
	binary.BigEndian.PutUint16(l, uint16(len(data2)))
	if _, err := writer.Write(l); err != nil {
		return err
	}
	if _, err := writer.Write(data2); err != nil {
		return err
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	return nil
}

func encodeRelay(reader *bufio.Reader, writer *bufio.Writer, wg *sync.WaitGroup) {
	defer wg.Done()
	data := make([]byte, bufferSize)
	for {
		n, err := reader.Read(data[:bufferSize-64])
		if err != nil {
			return
		}
		err = encodeSend(writer, data, n)
		if err != nil {
			return
		}
	}
}

func decodeRecevice(reader *bufio.Reader, data []byte) ([]byte, error) {
	l := make([]byte, 2)
	_, err := io.ReadFull(reader, l)
	if err != nil {
		return nil, err
	}
	ll := binary.BigEndian.Uint16(l)
	_, err = io.ReadFull(reader, data[:ll])
	if err != nil {
		return nil, err
	}
	data2, err := DecryptAES([]byte(key), data[:ll])
	if err != nil {
		return nil, err
	}
	data2, err = Unpad(data2, 16)
	if err != nil {
		return nil, err
	}
	return data2, nil
}

func decodeRelay(reader *bufio.Reader, writer *bufio.Writer, wg *sync.WaitGroup) {
	defer wg.Done()
	data := make([]byte, bufferSize)
	for {
		data2, err := decodeRecevice(reader, data)
		if err != nil {
			return
		}
		if _, err := writer.Write(data2); err != nil {
			return
		}
		if err := writer.Flush(); err != nil {
			return
		}
	}
}

func Relay(reader *bufio.Reader, writer *bufio.Writer, wg *sync.WaitGroup) {
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

func identify(reader *bufio.Reader, writer *bufio.Writer) (bool, error) {
	data := make([]byte, bufferSize)
	now := 0
	uLen := make([]byte, 2)
	pLen := make([]byte, 2)
	binary.BigEndian.PutUint16(uLen, uint16(len(userName)))
	copy(data[now:], uLen)
	now += 2
	copy(data[now:], []byte(userName))
	now += len(userName)
	binary.BigEndian.PutUint16(pLen, uint16(len(password)))
	copy(data[now:], pLen)
	now += 2
	copy(data[now:], []byte(password))
	now += len(password)
	err := encodeSend(writer, data, now)
	if err != nil {
		return false, err
	}
	data, err = decodeRecevice(reader, data)
	if err != nil {
		return false, err
	}
	return data[0] == 0x00, nil
}

func dealRequest(reader *bufio.Reader, writer *bufio.Writer, reads *bufio.Reader) error {
	ver, err := reads.ReadByte()
	if err != nil {
		return err
	}
	if ver != 0x05 {
		return errors.New("unexpected protocol")
	}
	cmd, err := reads.ReadByte()
	if err != nil {
		return err
	}
	if cmd == 0x00 || cmd > 0x03 {
		return errors.New("unexpected command")
	}
	_, err = reads.Discard(1)
	if err != nil {
		return err
	}
	atyp, err := reads.ReadByte()
	if err != nil {
		return err
	}
	if reads.Buffered() <= 2 {
		return errors.New("unexpected message")
	}
	var ip net.IP
	if atyp == 0x01 || atyp == 0x04 {
		addr := make([]byte, atyp*4)
		_, err := io.ReadFull(reads, addr)
		if err != nil {
			return err
		}
		ip = net.IP(addr)
	} else if atyp == 0x03 {
		l, err := reads.ReadByte()
		if err != nil {
			return err
		}
		addr := make([]byte, l)
		_, err = io.ReadFull(reads, addr)
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
	_, err = io.ReadFull(reads, sport)
	if err != nil {
		return err
	}
	port := binary.BigEndian.Uint16(sport)
	//fmt.Println(ip.String(), port)
	conn, err := net.Dial("tcp", ip.String()+":"+strconv.Itoa(int(port)))
	//fmt.Println(err)
	if err != nil {
		return err
	}
	defer conn.Close()
	now := 0
	data := make([]byte, bufferSize)
	copy(data[now:], []byte{0x05, 0x00, 0x00})
	now += 3
	localaddr := conn.LocalAddr().(*net.TCPAddr)
	if len(localaddr.IP) == 4 {
		copy(data[now:], []byte{0x01})
	} else {
		copy(data[now:], []byte{0x04})
	}
	now++
	copy(data[now:], []byte(localaddr.IP))
	now += len(localaddr.IP)
	ports := make([]byte, 2)
	binary.BigEndian.PutUint16(ports, uint16(localaddr.Port))
	copy(data[now:], ports)
	now += 2
	_, err = writer.WriteString(string(data[:now]))
	if err != nil {
		return err
	}
	err = writer.Flush()
	if err != nil {
		return err
	}
	wg := new(sync.WaitGroup)
	wg.Add(2)
	go Relay(reader, bufio.NewWriter(conn), wg)
	go Relay(bufio.NewReader(conn), writer, wg)
	wg.Wait()
	return nil
}

func connectRelayServer(reader *bufio.Reader, writer *bufio.Writer) error {
	conn, err := net.Dial("tcp", serverIP+":"+serverPort)
	if err != nil {
		return err
	}
	defer conn.Close()
	bo, err := identify(bufio.NewReader(conn), bufio.NewWriter(conn))
	if err != nil {
		return err
	}
	if !bo {
		return errors.New("uncorrect password")
	}

	data := make([]byte, bufferSize)
	n, err := reader.Read(data)
	if err != nil {
		return err
	}
	if !global {
		err := dealRequest(reader, writer, bufio.NewReader(strings.NewReader(string(data[:n]))))
		//fmt.Println("!!")
		if err == nil {
			return nil
		}
	}
	err = encodeSend(bufio.NewWriter(conn), data, n)
	if err != nil {
		return err
	}
	data, err = decodeRecevice(bufio.NewReader(conn), data)
	if err != nil {
		return err
	}
	_, err = writer.Write(data)
	if err != nil {
		return err
	}
	err = writer.Flush()
	if err != nil {
		return err
	}
	wg := new(sync.WaitGroup)
	wg.Add(2)
	go encodeRelay(reader, bufio.NewWriter(conn), wg)
	go decodeRelay(bufio.NewReader(conn), writer, wg)
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
	connectRelayServer(reader, writer)
}

func Run() {
	client, err := net.Listen("tcp", ":"+listenPort)
	if err != nil {
		log.Println(err)
		return
	}
	fmt.Println("listening at [::]" + listenPort)
	for {
		conn, err := client.Accept()
		if err != nil {
			log.Println(err)
		}
		go Serve(conn)
	}
}

func main() {
	ReadConfig()
	Run()
}
