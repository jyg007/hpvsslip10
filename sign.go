package main


import (
	//"bytes"
	"encoding/hex"
	"context"
	"crypto/sha256"
	"fmt"
	"os"

	"hpvsslip10/ep11"
	pb "hpvsslip10/grpc"
)

func main()( ) {

	cryptoClient := getGrep11Server()
	defer disconnectGrep11Server() 

    sk := make([]byte, hex.DecodedLen(len(os.Args[2])))
    hex.Decode(sk, []byte(os.Args[2]))

    //*****************************************************************
	signData := sha256.Sum256([]byte(os.Args[1]))
	signRequest := &pb.SignSingleRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PrivKey:  sk,
		Data:  signData[:],
	}

	SignResponse, err := cryptoClient.SignSingle(context.Background(), signRequest)
	if err != nil {
		panic(fmt.Errorf("Sign error: %s", err))
	}
 	//*****************************************************************
	
 	sign := make([]byte, hex.EncodedLen(len(SignResponse.Signature)))
        hex.Encode(sign, SignResponse.Signature)
        fmt.Println("signature: " +string(sign))

}
