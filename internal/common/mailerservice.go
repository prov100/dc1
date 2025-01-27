package common

import (
	"os"
	"path/filepath"

	"github.com/prov100/dc1/internal/config"
	"go.uber.org/zap"
	gomail "gopkg.in/gomail.v2"
)

// MailerIntf interface to the Mailer
type MailerIntf interface {
	SendConfirmationMail(hostURL string, userEmail string, emailConfirmationToken string, requestID string) error
	SendResetPasswordMail(hostURL string, userEmail string, resetToken string, requestID string) error
	SendChangeMail(hostURL string, userEmail string, newEmail string, resetToken string, requestID string) error
	SendMail(msg Email) error
}

// MailerService Pointer to mailer
type MailerService struct {
	log    *zap.Logger
	Mailer *gomail.Dialer
}

// Email - for sending email notifications
type Email struct {
	From    string
	To      string
	Subject string
	Body    string
	Cc      string
}

// NewMailerService get connection to mailer and create a MailerService struct
func NewMailerService(log *zap.Logger, mailerOpt *config.MailerOptions) (*MailerService, error) {
	mailer := gomail.NewDialer(mailerOpt.Server, mailerOpt.Port, mailerOpt.User, mailerOpt.Password)

	mailerService := &MailerService{}
	mailerService.Mailer = mailer
	mailerService.log = log

	return mailerService, nil
}

// CreateMailerService -- init mailer
func CreateMailerService(log *zap.Logger, mailerOpt *config.MailerOptions) (*MailerService, error) {
	mailerService, err := NewMailerService(log, mailerOpt)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 750), zap.Error(err))
		return nil, err
	}
	return mailerService, nil
}

// SendConfirmationMail - used for sending confirmation email
func (mailerService *MailerService) SendConfirmationMail(hostURL string, userEmail string, emailConfirmationToken string, requestID string) error {
	pwd, _ := os.Getwd()
	viewpath := pwd + filepath.FromSlash("/internal/common/views/confirmation.html")
	templateData := struct {
		Title string
		URL   string
	}{
		Title: "Confirmation",
		URL:   "http://" + hostURL + "/u/confirmation/" + emailConfirmationToken,
	}
	confirmationEmail, err := ParseTemplate(viewpath, templateData)
	if err != nil {
		mailerService.log.Error("Error", zap.String("reqid", requestID), zap.Int("msgnum", 260), zap.Error(err))
		return err
	}

	email := Email{
		To:      userEmail,
		Subject: "Confirmation",
		Body:    confirmationEmail,
	}

	err = mailerService.SendMail(email)
	if err != nil {
		mailerService.log.Error("Error", zap.String("reqid", requestID), zap.Int("msgnum", 261), zap.Error(err))
		return err
	}
	return nil
}

// SendResetPasswordMail - used for sending reset password email
func (mailerService *MailerService) SendResetPasswordMail(hostURL string, userEmail string, resetToken string, requestID string) error {
	pwd, _ := os.Getwd()
	viewpath := pwd + filepath.FromSlash("/internal/common/views/reset_password.html")

	templateData := struct {
		Title string
		URL   string
	}{
		Title: "Reset Password",
		URL:   "http://" + hostURL + "/u/reset_password/" + resetToken,
	}

	resetPasswordEmail, err := ParseTemplate(viewpath, templateData)
	if err != nil {
		mailerService.log.Error("Error", zap.String("reqid", requestID), zap.Int("msgnum", 262), zap.Error(err))
		return err
	}

	email := Email{
		To:      userEmail,
		Subject: "Reset Passowrd",
		Body:    resetPasswordEmail,
	}

	err = mailerService.SendMail(email)
	if err != nil {
		mailerService.log.Error("Error", zap.String("reqid", requestID), zap.Int("msgnum", 260), zap.Error(err))
		return err
	}

	return nil
}

// SendChangeMail - used for sending change email
func (mailerService *MailerService) SendChangeMail(hostURL string, userEmail string, newEmail string, resetToken string, requestID string) error {
	pwd, _ := os.Getwd()
	viewpath := pwd + filepath.FromSlash("/internal/common/views/change_email.html")

	templateData := struct {
		Title string
		URL   string
	}{
		Title: "Change Email",
		URL:   "http://" + hostURL + "/users/change_email/" + resetToken,
	}

	changeEmail, err := ParseTemplate(viewpath, templateData)
	if err != nil {
		mailerService.log.Error("Error", zap.String("user", userEmail), zap.String("reqid", requestID), zap.Int("msgnum", 264), zap.Error(err))
		return err
	}

	email := Email{
		To:      newEmail,
		Subject: "Change Email",
		Body:    changeEmail,
	}

	err = mailerService.SendMail(email)
	if err != nil {
		mailerService.log.Error("Error", zap.String("user", userEmail), zap.String("reqid", requestID), zap.Int("msgnum", 264), zap.Error(err))
		return err
	}

	return nil
}

// SendMail - used for sending email
func (mailerService *MailerService) SendMail(msg Email) error {
	m := gomail.NewMessage()
	m.SetHeader("From", mailerService.Mailer.Username)
	m.SetHeader("To", msg.To)
	m.SetHeader("Subject", msg.Subject)
	m.SetBody("text/html", msg.Body)

	err := mailerService.Mailer.DialAndSend(m)
	if err != nil {
		mailerService.log.Error("Error", zap.Int("msgnum", 259), zap.Error(err))
		return err
	}
	return nil
}
