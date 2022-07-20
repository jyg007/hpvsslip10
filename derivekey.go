package main

import (
	"encoding/hex"
	"context"
	"fmt"
	"os"
	"strconv"
	"encoding/asn1"
	 "bytes"
	 
	"hpvsslip10/ep11"
	pb "hpvsslip10/grpc"
)

var cryptoClient pb.CryptoClient

var ecParameters []byte 

var slip10DerivType = map[string]pb.BTCDeriveParm_BTCDeriveType{
    "PRV2PRV" :5,
    "PRV2PUB" :6,
    "PUB2PUB" :7,  // unsupported
    "MASTERK" :8,
}


func slip10_deriveKey(deriveType string, childKeyIndex uint64, hardened bool, baseKey []byte, chainCode []byte) ([]byte, []byte) {

	if hardened {
		childKeyIndex += 0x80000000
	}

	deriveKeyRequest := &pb.DeriveKeyRequest{
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_IBM_BTC_DERIVE,
			Parameter: &pb.Mechanism_BTCDeriveParameter{
				BTCDeriveParameter: &pb.BTCDeriveParm{
					Type:          slip10DerivType[deriveType],
					ChildKeyIndex: childKeyIndex,
					ChainCode:     chainCode,
					Version:       1,
				},
			},
		},
		Template: AttributeMap(
			ep11.EP11Attributes{
				ep11.CKA_VERIFY:          true,
				ep11.CKA_EXTRACTABLE:     false,
				ep11.CKA_DERIVE:          true,
				ep11.CKA_KEY_TYPE:        ep11.CKK_ECDSA,
				ep11.CKA_VALUE_LEN:       (uint64)(0),
				ep11.CKA_IBM_USE_AS_DATA: true,
				ep11.CKA_EC_PARAMS:       ecParameters,
			},
		),
		BaseKey: baseKey,
	}

	deriveKeyResponse, err := cryptoClient.DeriveKey(context.Background(), deriveKeyRequest)
	if err != nil {
		panic(fmt.Errorf("Derived Child Key request: %+v error: %s", deriveKeyRequest, err))
	}

	return deriveKeyResponse.NewKeyBytes, deriveKeyResponse.CheckSum
}



func main() {

    cryptoClient = getGrep11Server()
   	defer disconnectGrep11Server() 

    ecParameters, _ = asn1.Marshal(asn1.ObjectIdentifier{1, 3, 132, 0, 10})  // CurveSecp256k1 

   	seed := make([]byte, hex.DecodedLen(len(os.Getenv("MASTERSEED"))))
    hex.Decode(seed, []byte(os.Getenv("MASTERSEED")))

    var Chaincode []byte
    var prevSk []byte
    var prevChaincode []byte

    path := bytes.Split([]byte(os.Args[1]),[]byte("/"))
 
    Sk , Chaincode := slip10_deriveKey("MASTERK", 0, false, seed,nil)
    CheckSumHex := make([]byte, hex.EncodedLen(len(Chaincode)))
 
  	var index uint64
  	var hardened bool
    for i:=1; i<len(path); i++ {
    	if path[i][len(path[i])-1] == []byte("h")[0] {
    		hardened = true
    		index , _= strconv.ParseUint(string(path[i][:len(path[i])-1]),10,64)
    	} else {
    		hardened = false
      		index ,_ = strconv.ParseUint(string(path[i]),10,64)
    	}

   		prevSk = Sk
    	prevChaincode = Chaincode

	    Sk , Chaincode = slip10_deriveKey("PRV2PRV", index, hardened, Sk, Chaincode)   	
    }

    sKeyHex := make([]byte, hex.EncodedLen(len(Sk)))
    hex.Encode(sKeyHex, Sk)
    fmt.Println("Derived Private Key: " +string(sKeyHex)+"\n")

    if len(path)>1 {
    	pk_tmp , _ := slip10_deriveKey("PRV2PUB", index, hardened, prevSk, prevChaincode)
 		pk, _ := GetPubkeyBytesFromSPKI(pk_tmp)
   	    pKeyHex := make([]byte, hex.EncodedLen(len(pk)))
	    hex.Encode(pKeyHex, pk)
	    fmt.Println("Derived Public Key: " +string(pKeyHex)+"\n")
	}

	CheckSumHex = make([]byte, hex.EncodedLen(len(Chaincode)))
    hex.Encode(CheckSumHex, Chaincode)
   	fmt.Println("chain Code: " +string(CheckSumHex)+"\n")
  }