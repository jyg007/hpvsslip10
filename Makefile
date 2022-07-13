all: derivekey  sign verify createseed 

createkey: createkey.go connect.go util.go
	go build createkey.go connect.go util.go

derivekey: derivekey.go connect.go util.go
	go build derivekey.go connect.go util.go

sign: sign.go connect.go util.go
	go build sign.go connect.go util.go

verify: verify.go connect.go util.go
	go build verify.go connect.go util.go

createseed: createseed.go connect.go util.go
	go build createseed.go connect.go util.go

