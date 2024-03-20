package main


import (
	//"bytes"
	"encoding/hex"
	"context"
	"fmt"
	"os"
	//"bytes"
	"hpvsslip10/ep11"
	pb "hpvsslip10/grpc"
 "github.com/ethereum/go-ethereum/ethclient"

 "math/big"
	
	//"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
           "github.com/ethereum/go-ethereum/common"
 //       "github.com/ethereum/go-ethereum/common/hexutil"
        "github.com/ethereum/go-ethereum/core/types"


)


func main()( ) {

	cryptoClient := getGrep11Server()
	defer disconnectGrep11Server() 


    client, err := ethclient.Dial("https://rpc.notadegen.com/base/sepolia")
    if err != nil {
            fmt.Println("fail to connect.")
            return
    }


    sk := make([]byte, hex.DecodedLen(len(os.Args[1])))
    hex.Decode(sk, []byte(os.Args[1]))



    // Clé publique au format compressé (64 bytes)
    pk:=os.Args[2]

    publicKeyBytes:= make([]byte, 65)
    hex.Decode(publicKeyBytes,[]byte(pk))

    // Convertir la clé publique en type ecdsa.PublicKey
    publicKey, err := crypto.UnmarshalPubkey(publicKeyBytes)
    if err != nil {
        fmt.Println("Erreur lors de la conversion de la clé publique :", err)
        return
    }

    // Obtenir l'adresse Ethereum à partir de la clé publique
    fromAddress := crypto.PubkeyToAddress(*publicKey)

    // Afficher l'adresse Ethereum
    fmt.Println("Adresse Ethereum :", fromAddress.Hex())

 
    //*****************************************************************


    nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
    if err != nil {
                fmt.Println("failed to get nonce")
    }
        
    value := big.NewInt(int64(0.00000001 * 1000000000000000000)) // in wei (0.001 eth)
    gasLimit := uint64(21000)                                      // in units
    gasPrice, err := client.SuggestGasPrice(context.Background())
    if err != nil {
                fmt.Println("fail to get gas price")
    }

    toAddress := common.HexToAddress(os.Args[3])
    var data []byte
    
    tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, data)

  /*  chainID, err := client.NetworkID(context.Background())
    if err != nil {
        fmt.Println(err)
            fmt.Println("fail to get chain ID")
            return
    }*/
    decimalValue := int64(84532)
    chainID := new(big.Int).SetInt64(decimalValue)


    signer := types.NewEIP155Signer(chainID)
    signData := signer.Hash(tx)

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
    copy(sig[:32],r.Bytes())
    copy(sig[32:64],s.Bytes())


fmt.Println("signature: 0x" +hex.EncodeToString(sig))
    signedTx, err := tx.WithSignature(signer, sig)

    fmt.Println("signedtx",signedTx)
    if err != nil {
            fmt.Println("failed to sign ")
    }

    err = client.SendTransaction(context.Background(), signedTx)
    if err != nil {
        fmt.Println(err)
            fmt.Println("fail to broadcast to ethereum")
            return
    }
    fmt.Println("Pls check result with following link:")
    fmt.Printf("            https://sepolia.basescan.org/tx/%s \n", signedTx.Hash().Hex())

}
