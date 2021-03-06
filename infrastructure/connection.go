package infrastructure

import (
	"bufio"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
)

type Connection struct {
	rawConn net.Conn
	reader  *bufio.Reader
	writer  *bufio.Writer
}

func NewConnection(conn net.Conn) Connection {
	return Connection{
		conn,
		bufio.NewReader(conn),
		bufio.NewWriter(conn),
	}
}

func (conn *Connection) WriteByte(b byte) error {
	return conn.writer.WriteByte(b)
}

func (conn *Connection) Write(bytes []byte) (int, error) {
	return conn.writer.Write(bytes)
}

func (conn *Connection) Flush() error {
	return conn.writer.Flush()
}

func (conn *Connection) ReadByte() (byte, error) {
	return conn.reader.ReadByte()
}

func (conn *Connection) Read(buf []byte) (int, error) {
	return conn.reader.Read(buf)
}

func (conn *Connection) Close() {
	if err := conn.rawConn.Close(); err != nil {
		log.Info("Failed to close connection, ", err)
	}
}

func (conn *Connection) PeekByte() (byte, error) {
	bytes, err := conn.reader.Peek(1)
	if err != nil {
		return 0, err
	}

	return bytes[0], nil
}

func (conn *Connection) Writer() io.Writer {
	return conn.writer
}

func (conn *Connection) Reader() io.Reader {
	return conn.reader
}
