package utils

import (
	"context"
	"fmt"
	"os"

	brevo "github.com/getbrevo/brevo-go/lib"
)

func SendMail(userEmail string, subject string, html string) (bool, error) {

	ctx := context.Background()

	cfg := brevo.NewConfiguration()
	cfg.AddDefaultHeader("api-key", os.Getenv("BREVO_API_KEY"))
	cfg.AddDefaultHeader("partner-key", os.Getenv("BREVO_API_KEY"))

	br := brevo.NewAPIClient(cfg)

	sender := brevo.SendSmtpEmailSender{
		Name:  "Abode Server",
		Email: "oyelowomayowa@gmail.com",
	}

	to := []brevo.SendSmtpEmailTo{
		{
			Email: userEmail,
		},
	}

	email := brevo.SendSmtpEmail{
		Sender:      &sender,
		To:          to,
		Subject:     subject,
		HtmlContent: html,
	}

	result, resp, err := br.TransactionalEmailsApi.SendTransacEmail(ctx, email)

	if err != nil {
		return false, fmt.Errorf("failed to send email: %w", err)
	}
	if resp.StatusCode != 201 {
		return false, fmt.Errorf("failed to send email: received status code %d", resp.StatusCode)
	}
	fmt.Printf("Email sent successfully! Result: %v\n", result)
	return true, nil

	// Handle any errors that occur during sending
	// if err != nil {
	// 	return false, err
	// }
	// return true, nil
}
