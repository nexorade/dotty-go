package hedwig

import (
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

func GetOrchestrator() *Orchestrator {
	if orchestrator != nil {
		return orchestrator
	}
	ch := make(chan gomail.Message, BUFFER)
	conf := dialerConfig{
		host:     "smtp.hostinger.com",
		port:     587,
		username: "noreply@nexorade.com",
		password: "Demure@#$123",
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

			gomail.Send(orchestrator.connection, &e)
		}
	}
}

func CloseOrchastrator() {
	close(orchestrator.queue)
	orchestrator = &Orchestrator{}
}

func (o *Orchestrator) SendOTP(to string, otp string) {
	m := gomail.NewMessage()
	m.SetHeader("From", "noreply@nexorade.com")
	m.SetHeader("To", to)
	m.SetHeader("Subject", "Welcome to Dotty")
	m.SetBody("text/plain", "Your OTP: "+otp)

	o.queue <- *m
}
