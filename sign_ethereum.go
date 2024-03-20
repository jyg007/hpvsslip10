package main


import (
	//"bytes"
	"encoding/hex"
	"context"
	"fmt"
	"os"
	"bytes"
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
	/*
	 msg := make([]byte, hex.DecodedLen(len(os.Args[1])))
     hex.Decode(msg, []byte(os.Args[1]))
   messageHash := crypto.Keccak256(msg)*/

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

    r := new(big.Int).SetBytes(SignResponse.Signature[:32])
    s := new(big.Int).SetBytes(SignResponse.Signature[32:64])

	n := new(big.Int)
    n.SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
    two := big.NewInt(2)

    /*
            URL: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2.md
            All transaction signatures whose s-value is greater than secp256k1n/2 are now considered invalid.
            The ECDSA recover precompiled contract remains unchanged and will keep accepting high s-values; this is useful
            e.g. if a contract recovers old Bitcoin signatures.
    */

    halfN := new(big.Int)
    halfN.Div(n, two)

    if halfN.Cmp(s) == -1 {
           s = s.Sub(n, s)
    } 
    
    sig := make([]byte,65)
    //copy(sig,SignResponse.Signature[:])
    copy(sig[:32],r.Bytes())
    copy(sig[32:64],s.Bytes())
	sig[64] = 0x00

    publicK, err := crypto.Ecrecover(signData[:], sig)
    if err != nil {
        fmt.Println("Error recovering public key:", err)
        return
    } else if ! bytes.Equal(publicKeyBytes,publicK) {
			sig[64] = 0x01
    		// Recover public key from signature
    		publicK, err = crypto.Ecrecover(signData[:], sig)
    		if err != nil {
        		fmt.Println("Error recovering public key:", err)
        		return
    		}
    	} 
 
  //  fmt.Println("Public Key", hex.EncodeToString(publicK))
    
    sig[64]+=0x1b

    fmt.Println("signature: 0x" +hex.EncodeToString(sig))

}
