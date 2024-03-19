package main

import (
	"encoding/hex"
		"encoding/asn1"
	"context"
	"fmt"
	"os"
	"crypto/sha256"

	"hpvsslip10/ep11"
	pb "hpvsslip10/grpc"
)


func main()( ) {

    cryptoClient := getGrep11Server()
   	defer disconnectGrep11Server() 

    pk := make([]byte, hex.DecodedLen(len(os.Args[3])))
    hex.Decode(pk, []byte(os.Args[3]))

    key := ecPubKeyASN{	 Ident: ecKeyIdentificationASN{ 
    								KeyType : asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}, 
    								Curve   : asn1.ObjectIdentifier{1, 3, 132, 0, 10},
    							},
    					 Point: asn1.BitString{ Bytes: pk, BitLength: 8*len(pk)},
    		}

    pkk , err := asn1.Marshal(key)
    if (err != nil) {
        panic(err)
    }

    sign := make([]byte, hex.DecodedLen(len(os.Args[2])))
    hex.Decode(sign, []byte(os.Args[2]))

	signData := sha256.Sum256([]byte(os.Args[1]))
 
    //*****************************************************************
	verifyRequest := &pb.VerifySingleRequest{
		Mech:   	&pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PubKey: 	pkk,
		Data:       []byte(signData[:]),
		Signature:  sign,
	}

	_, err = cryptoClient.VerifySingle(context.Background(), verifyRequest)
	if ok, ep11Status := Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			panic(fmt.Errorf("Invalid signature"))
		} else {
			panic(fmt.Errorf("Verify error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
		}
	}
	fmt.Println("Verified")
	//*****************************************************************
}