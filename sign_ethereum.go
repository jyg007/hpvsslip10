package main


import (
	//"bytes"
	"encoding/hex"
	"context"
	"fmt"
	"os"
	"hpvsslip10/ep11"
	pb "hpvsslip10/grpc"
    "encoding/asn1"
 "math/big"
	
	//"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

type ASN1PublicKey struct {
	OID    asn1.ObjectIdentifier
	Public asn1.BitString
}


func main()( ) {

	cryptoClient := getGrep11Server()
	defer disconnectGrep11Server() 


    // Clé publique au format compressé (64 bytes)
    pk:=os.Args[3]

    publicKeyBytes:= make([]byte, 65)
    hex.Decode(publicKeyBytes,[]byte(pk))

    // Convertir la clé publique en type ecdsa.PublicKey
    publicKey, err := crypto.UnmarshalPubkey(publicKeyBytes)
    if err != nil {
        fmt.Println("Erreur lors de la conversion de la clé publique :", err)
        return
    }

    // Obtenir l'adresse Ethereum à partir de la clé publique
    address := crypto.PubkeyToAddress(*publicKey)

    // Afficher l'adresse Ethereum
    fmt.Println("Adresse Ethereum :", address.Hex())

    sk := make([]byte, hex.DecodedLen(len(os.Args[2])))
    hex.Decode(sk, []byte(os.Args[2]))

    //*****************************************************************
    

	messageHash := crypto.Keccak256([]byte(os.Args[1]))

	prefix := "\x19Ethereum Signed Message:\n32"
	messageWithPrefix := append([]byte(prefix), messageHash...)

	// Calculer le hash Keccak256 du message avec le préfixe
	signData := crypto.Keccak256(messageWithPrefix)
	

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
	 //   sig := toByte(sigResponse.Signature)
        r := new(big.Int).SetBytes(SignResponse.Signature[:32])
        //s := new(big.Int).SetBytes(sig[32:64])

  		n := new(big.Int)
    	n.SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)

    
    	suf:="1b"
    	if (n.Cmp(r)==1) {
    		suf="1c"
    	}


 	   	sign := make([]byte, hex.EncodedLen(len(SignResponse.Signature)))
       	hex.Encode(sign, SignResponse.Signature)
       	fmt.Println("signature: 0x" +string(sign)+suf)

}
