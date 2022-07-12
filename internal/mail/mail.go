package mail

import (
	"context"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/trycourier/courier-go/v2"
)

func SendMail(email, content string) (error, bool) {
	var courier_secret = []byte(os.Getenv("COURIER_TOKEN"))
	client := courier.CreateClient(string(courier_secret), nil)

	requestID, err := client.SendMessage(
		context.Background(),
		courier.SendMessageRequestBody{
			Message: map[string]interface{}{
				"to": map[string]string{
					"email": email,
				},
				"template": "GPZ8XQAKMSMT0KNGV1WA91V2XDD5",
				"data": map[string]string{
					"content": content,
				},
			},
		},
	)

	if err != nil {
		logrus.Error(err)
		return err, false
	}

	logrus.Info(requestID)
	return nil, true
}
