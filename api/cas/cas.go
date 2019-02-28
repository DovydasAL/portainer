package cas

import (
	"encoding/xml"
	"fmt"
	"github.com/portainer/portainer"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

const (
	// ErrInvalidServiceTicket defines an error raised when the user Service Ticket is invalid
	ErrInvalidServiceTicket = portainer.Error("Service ticket is invalid")
)

// CASService represents a service used to authenticate users against a CAS Server
type Service struct {}

type Username struct {
	Username string `xml:"authenticationSuccess>user"`
}

func (*Service) ValidateServiceTicket(st string, settings *portainer.CASSettings) ([]byte, error) {
	v := url.Values{}
	v.Set("service", settings.CASRedirectURL)
	v.Set("ticket", st)
	var req *http.Request
	var err error
	if settings.UseServiceValidateEndpoint {
		req, err = http.NewRequest("POST", settings.CASServerURL + "cas/serviceValidate", strings.NewReader(v.Encode()))
	} else {
		req, err = http.NewRequest("POST", settings.CASServerURL + "cas/validate", strings.NewReader(v.Encode()))
	}
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return body, err
}


func (*Service) ExtractUsername(response []byte, settings *portainer.CASSettings) (string, error) {

	if settings.UseServiceValidateEndpoint {
		rq := new(Username)
		fmt.Printf("%v", string(response))
		err := xml.Unmarshal(response, &rq)
		if err != nil {
			return "", err
		}

		if rq.Username == "" {
			return "", portainer.Error("Unable to acquire username")
		}

		return rq.Username, nil
	}

	data := strings.Split(string(response), "\n")
	if data[0] == "no" {
		return "", portainer.Error("Invalid service ticket")
	}

	return data[1], nil
}


