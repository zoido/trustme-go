package trustme_test

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/zoido/trustme-go"
)

func exampleHandler(w http.ResponseWriter, r *http.Request) {
	if len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "Requires mTLS", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(r.TLS.PeerCertificates[0].Subject.CommonName))
}

func TestExample(t *testing.T) {
	ca := trustme.New(t)
	serverCert := ca.MustIssue(trustme.WithIP(net.ParseIP("127.0.0.1")))
	clientCert := ca.MustIssue(trustme.WithCommonName("TEST CLIENT"))

	serverConfig := serverCert.AsServerConfig()
	serverConfig.ClientAuth = tls.RequireAndVerifyClientCert
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		t.Error(err)
	}

	defer listener.Close()

	srv := http.Server{
		Handler: http.HandlerFunc(exampleHandler),
	}
	defer srv.Close()
	go srv.Serve(listener)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: clientCert.AsClientConfig(),
		},
		Timeout: time.Second * 5,
	}

	resp, err := client.Get(fmt.Sprintf("https://%s/", listener.Addr().String()))
	if err != nil {
		t.Error(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatal("Server did not return OK status")
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
	}
	if bytes.Compare(b, []byte("TEST CLIENT")) != 0 {
		t.Fatal("Server did not return expected peer CN")
	}
}

func Example() {
	ca := trustme.New(&testing.T{})

	srvCfg := ca.MustIssue(trustme.WithIP(net.ParseIP("127.0.0.1"))).AsServerConfig()
	srvCfg.ClientAuth = tls.RequireAndVerifyClientCert
	listener, _ := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	defer listener.Close()

	srv := http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(r.TLS.PeerCertificates) == 0 {
				http.Error(w, "Requires mTLS", http.StatusUnauthorized)
			}
		}),
	}
	defer srv.Close()
	go srv.Serve(listener)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: ca.MustIssue().AsClientConfig(),
		},
		Timeout: time.Second * 5,
	}

	client.Get(fmt.Sprintf("https://%s/", listener.Addr().String()))

	// ...
}
