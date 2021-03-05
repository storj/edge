// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/storj/gateway-mt/experimental/middleware/config"
	"github.com/storj/gateway-mt/experimental/middleware/project"
	"github.com/storj/gateway-mt/experimental/pkg/authc"
	"github.com/storj/minio/pkg/storj/middleware/signature"
	"github.com/storj/minio/pkg/storj/router/bucket"
	"storj.io/common/rpc/rpcpool"
	"storj.io/uplink"
)

func main() {
	ctx := context.Background()

	// Initialize the auth client.
	authBaseURL, err := url.Parse(os.Getenv("GMT_AUTH_URL"))
	if err != nil {
		panic(err)
	}

	authToken := os.Getenv("GMT_AUTH_TOKEN")
	if authToken == "" {
		panic(errors.New("auth token is not set"))
	}

	authClient, err := authc.New(authBaseURL, authToken)
	if err != nil {
		panic(err)
	}

	authHealthLiveOk, err := authClient.GetHealthLive(ctx)
	if !authHealthLiveOk {
		panic(err)
	}

	// Determine what our domain name should be.
	domain, ok := os.LookupEnv("GMT_DOMAIN")
	if !ok {
		domain = "localhost"
	}

	// Setup the server config.
	serverConfig := &config.Config{
		Domain: domain,
		UplinkConfig: &uplink.Config{
			DialTimeout: 3 * time.Second,
		},
		RPCPool: rpcpool.New(rpcpool.Options{
			// This needs to be on the order of the number of nodes in the
			// network. If it isn't, then each new request that comes in
			// will cause some amount of churn in the pool. If it is too
			// low, then almost all the connections are purged on each
			// request. If it is too high we run out of tcp ports.
			Capacity:       10000,
			KeyCapacity:    2,
			IdleExpiration: 2 * time.Minute,
		}),
		AuthClient: authClient,
	}

	// Configure the signature middleware.
	signature := &signature.Signature{
		SecretKey: authc.NewSecretGetter(authClient),
	}

	// Setup our handlers and routes.
	h := &Handler{}

	r := mux.NewRouter()

	r.Use(serverConfig.Middleware)
	r.Use(signature.Middleware)
	// TODO: add validation middleware
	r.Use(project.New().Middleware)

	bucket.Attach(serverConfig.Domain, r, h)
	ch := cors.AllowAll().Handler(r)

	// Start listening for requests.
	srv := &http.Server{
		Handler: ch,
		Addr:    "127.0.0.1:8888",

		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Println("Starting to listen...")

	log.Fatal(srv.ListenAndServe())
}
