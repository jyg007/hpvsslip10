all: derivekey  sign verify createseed sign_ethereum

derivekey: derivekey.go connect.go util.go
	go build $^ 

sign: sign.go connect.go util.go
	go build $^ 

sign_ethereum: sign_ethereum.go connect.go util.go
	go build $^ 

verify: verify.go connect.go util.go
	go build $^ 

createseed: createseed.go connect.go util.go
	go build $^ 

clean:
	rm derivekey  sign verify createseed

