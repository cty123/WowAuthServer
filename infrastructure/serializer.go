package infrastructure

import (
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
)

func Deserialize(conn *Connection, packet interface{}) error {
	value := reflect.ValueOf(packet).Elem()
	if value.Kind() != reflect.Struct {
		return errors.New("incorrect struct")
	}

	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		if !field.IsValid() || !field.CanSet() {
			return errors.New("field not settable")
		}

		switch field.Kind() {
		case reflect.Array:
			elementType := reflect.TypeOf(field.Interface()).Elem()
			if elementType.Kind() != reflect.Uint8 {
				return errors.New("unsupported array element type " + elementType.Name())
			}

			length := field.Len()
			buffer := make([]uint8, length)
			if _, err := conn.Read(buffer); err != nil {
				return errors.New("failed to read from socket")
			}

			reflect.Copy(field, reflect.ValueOf(buffer))
		case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			b, err := conn.ReadByte()
			if err != nil {
				return errors.New("failed to read from socket")
			}

			field.SetUint(uint64(b))
		default:
			fmt.Println(field.Kind())
		}
	}

	return nil
}

func Serialize(conn *Connection, packet interface{}) error {
	value := reflect.ValueOf(packet).Elem()
	if value.Kind() != reflect.Struct {
		return errors.New("incorrect struct")
	}

	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		if !field.IsValid() {
			return errors.New("field not settable")
		}

		switch field.Kind() {
		case reflect.Slice:
			elementType := reflect.TypeOf(field.Interface()).Elem()
			if elementType.Kind() != reflect.Uint8 {
				return errors.New("unsupported array element type " + elementType.Name())
			}

			if _, err := conn.Write(field.Bytes()); err != nil {
				return errors.New("failed to write to socket")
			}
		case reflect.Uint8:
			if err := conn.WriteByte(byte(field.Uint())); err != nil {
				return errors.New("failed to write to socket")
			}
		case reflect.Uint16:
			b := make([]byte, 2)
			binary.LittleEndian.PutUint16(b, uint16(field.Uint()))
			if _, err := conn.Write(b); err != nil {
				return errors.New("failed to write to socket")
			}
		case reflect.Uint32:
			b := make([]byte, 4)
			binary.LittleEndian.PutUint32(b, uint32(field.Uint()))
			if _, err := conn.Write(b); err != nil {
				return errors.New("failed to write to socket")
			}
		case reflect.Uint64:
			b := make([]byte, 8)
			binary.LittleEndian.PutUint64(b, field.Uint())
			if _, err := conn.Write(b); err != nil {
				return errors.New("failed to write to socket")
			}
		default:
			return errors.New("unsupported type")
		}
	}

	if err := conn.Flush(); err != nil {
		return err
	}

	return nil
}
