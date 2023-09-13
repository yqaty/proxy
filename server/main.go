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
	"sync"

	"github.com/spf13/viper"
)

var listenPort, key string

const bufferSize = 1 << 12

func ReadConfig() {
	viper.SetConfigName("config")
	viper.SetConfigType("json")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("%w", err))
	}
	key = viper.GetString("key")
	listenPort = viper.GetString("listen_port")
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
	iv := plainText[n : n+aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(plainText[:n], plainText[:n])
	return plainText[:n+aes.BlockSize], err
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

func encodeRelay(reader *bufio.Reader, writer *bufio.Writer, wg *sync.WaitGroup) {
	defer wg.Done()
	data := make([]byte, bufferSize)
	for {
		n, err := reader.Read(data[:bufferSize-64])
		if err != nil {
			return
		}
		data2, err := Pad(data, n, 16)
		if err != nil {
			return
		}
		data2, err = EncryptAES([]byte(key), data, len(data2))
		if err != nil {
			return
		}
		l := make([]byte, 2)
		binary.BigEndian.PutUint16(l, uint16(len(data2)))
		if _, err := writer.Write(l); err != nil {
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

func decodeRelay(reader *bufio.Reader, writer *bufio.Writer, wg *sync.WaitGroup) {
	defer wg.Done()
	data := make([]byte, bufferSize)
	for {
		l := make([]byte, 2)
		_, err := io.ReadFull(reader, l)
		if err != nil {
			return
		}
		ll := binary.BigEndian.Uint16(l)
		_, err = io.ReadFull(reader, data[:ll])
		if err != nil {
			return
		}
		data2, err := DecryptAES([]byte(key), data[:ll])
		if err != nil {
			return
		}
		data2, err = Unpad(data2, 16)
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
	go decodeRelay(reader, bufio.NewWriter(conn), wg)
	go encodeRelay(bufio.NewReader(conn), writer, wg)
	wg.Wait()
	return nil
}

func Serve(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReaderSize(conn, bufferSize)
	writer := bufio.NewWriterSize(conn, bufferSize)
	dealRequest(reader, writer)
}

func Run() {
	listener, err := net.Listen("tcp", ":"+listenPort)
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
	ReadConfig()
	Run()
}
