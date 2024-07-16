package bootlibrary

import (
	"io/ioutil"
	"crypto/tls"
	"crypto/x509"
	"log"
	"google.golang.org/grpc/credentials"
)


func TLSCred(ServerCA string, ClientCert string, ClientKey string) credentials.TransportCredentials {
	// Create TLS credentials and return handle

	serCA, err := ioutil.ReadFile(ServerCA)
	if err != nil {
		log.Fatal(err)
	}
        certPool := x509.NewCertPool()
        if !certPool.AppendCertsFromPEM(serCA) {
                log.Fatal("failed to add server CA's certificate")
        }

        // Load clients's certificate and private key
        serverCert, err := tls.LoadX509KeyPair(ClientCert, ClientKey)
        if err != nil {
                log.Fatal(err)
        }

        // Create the credentials and return it
        config := &tls.Config{
                Certificates: []tls.Certificate{serverCert},
                RootCAs:    certPool,
        }

        creds := credentials.NewTLS(config)
	return creds
}
