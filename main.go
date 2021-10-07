package main

import (
	"fmt"
	"github.com/cty123/trinity-auth-server/handler"
	"github.com/cty123/trinity-auth-server/infrastructure"
	"github.com/cty123/trinity-auth-server/service"
	log "github.com/sirupsen/logrus"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"net"
)

func main() {
	// Establishing database connection
	db, _ := gorm.Open(mysql.New(mysql.Config{
		DSN:                       "root:19971112@tcp(127.0.0.1:3306)/auth?charset=utf8&parseTime=True&loc=Local",
		DefaultStringSize:         256,
		DisableDatetimePrecision:  true,
		DontSupportRenameIndex:    true,
		DontSupportRenameColumn:   true,
		SkipInitializeWithVersion: false,
	}), &gorm.Config{})

	// Initialize services
	accountService := service.NewAccountService(db)

	// Initialize handlers
	loginHandler := handler.NewLoginHandler(accountService)

	log.Info("Server started listening on port 3724")

	listener, err := net.Listen("tcp", "localhost:3724")
	if err != nil {
		fmt.Println("Failed to start the server")
		return
	}

	// Start accept loop to handle login requests
	for {
		socket, err := listener.Accept()
		if err != nil {
			fmt.Println("Failed to accept socket, " + err.Error())
		}

		conn := infrastructure.NewConnection(socket)
		go loginHandler.Handle(conn)
	}
}
