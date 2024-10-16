package hedwig

import (
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
	"gopkg.in/gomail.v2"
)

type dialerConfig struct {
	host     string
	port     int
	username string
	password string
}

type Orchestrator struct {
	queue      chan gomail.Message
	connection gomail.SendCloser
}

const (
	BUFFER = 100
)

var orchestrator *Orchestrator

func InitialiseOrchestrator() {
	if orchestrator != nil {
		panic("Orchestrator can be initialised only once")
	}
	ch := make(chan gomail.Message, BUFFER)
	conf := dialerConfig{
		host:     os.Getenv("SMTP_HOST"),
		port:     587,
		username: os.Getenv("SMTP_USERNAME"),
		password: os.Getenv("SMTP_PASSWORD"),
	}
	dialer := gomail.NewDialer(conf.host, conf.port, conf.username, conf.password)
	connection, err := dialer.Dial()
	if err != nil {
		panic(err)
	}
	newo := Orchestrator{
		queue:      ch,
		connection: connection,
	}
	orchestrator = &newo
	go orchestrate(orchestrator)

}

func GetOrchestrator() *Orchestrator {
	if orchestrator == nil {
		panic("Uninitialised orchaestrator")
	}
	return orchestrator
}

func orchestrate(orchestrator *Orchestrator) {
	for {
		select {
		case e, ok := <-orchestrator.queue:
			if !ok {
				orchestrator.connection.Close()
				break
			}

			sendErr := gomail.Send(orchestrator.connection, &e)

			if sendErr != nil {
				log.Error().Str("email-send-error", sendErr.Error())
			}
		}
	}
}

func CloseOrchastrator() {
	close(orchestrator.queue)
	orchestrator = &Orchestrator{}
}

func (o *Orchestrator) SendPasswordResetLink(to string, token string) bool {
	link := fmt.Sprintf("<h4>Please click the <a href='%s%s'>link</a> to reset your password</h4>", os.Getenv("PASSWORD_RESET_LINK"), token)
	m := gomail.NewMessage()
	m.SetHeader("From", "noreply@nexorade.com")
	m.SetHeader("To", to)
	m.SetHeader("Subject", "Password Reset Link")
	m.SetBody("text/html", link)

	o.queue <- *m
	return true
}

func (o *Orchestrator) SendOTP(to string, otp string) bool {
	m := gomail.NewMessage()
	m.SetHeader("From", "noreply@nexorade.com")
	m.SetHeader("To", to)
	m.SetHeader("Subject", "Welcome to Dotty")
	m.SetBody("text/plain", "Your OTP: "+otp)

	o.queue <- *m
	return true
}
