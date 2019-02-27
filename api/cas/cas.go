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

func (*Service) ValidateServiceTicket(st string, settings *portainer.CASSettings) (string, error) {
	v := url.Values{}
	v.Set("service", settings.CASRedirectURL)
	v.Set("ticket", st)
	var req *http.Request
	var err error
	if settings.UseServiceValidateEndpoint {
		req, err = http.NewRequest("POST", settings.CASServerURL + "/cas/serviceValidate", strings.NewReader(v.Encode()))
	} else {
		req, err = http.NewRequest("POST", settings.CASServerURL + "/cas/validate", strings.NewReader(v.Encode()))
	}
	if err != nil {
		return "", err
	}

	client := &http.Client{}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r, err := client.Do(req)
	if err != nil {
		return "", err
	}

	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return "", err
	}

	if settings.UseServiceValidateEndpoint {
		rq := new(Username)
		fmt.Printf("%v", string(body))
		err := xml.Unmarshal(body, &rq)
		if err != nil {
			return "", err
		}
		if rq.Username == "" {
			return "", portainer.Error("Unable to acquire username")
		}
		return rq.Username, nil
	} else {
		data := strings.Split(string(body), "\n")
		if data[0] == "no" {
			return "", portainer.Error("Invalid service ticket")
		}
		return data[1], nil
	}


}


