/*******************************************************************************
* Copyright 2022 IBM Corp.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*******************************************************************************/

package main

import (
	"context"
	"fmt"
	"os"
	"encoding/hex"
	"hpvsslip10/ep11"
	pb "hpvsslip10/grpc"
)

var cryptoClient pb.CryptoClient

func main() {

   	secretPlainVal := make([]byte, hex.DecodedLen(len(os.Args[1])))
    hex.Decode(secretPlainVal, []byte(os.Args[1]))

	secretPlainLen := len(secretPlainVal)

	if secretPlainLen != 64 {
		panic(fmt.Errorf("Invalid plain secret"))
	}

    cryptoClient = getGrep11Server()
    defer disconnectGrep11Server() 


   	// Create an ephemeral AES key
	aesKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_VALUE_LEN:   256 / 8,
		ep11.CKA_WRAP:        true,
		ep11.CKA_UNWRAP:      true,
		ep11.CKA_ENCRYPT:     true,
		ep11.CKA_DECRYPT:     true,
		ep11.CKA_EXTRACTABLE: true,
		ep11.CKA_TOKEN:       true,
	}

	aesGenerateKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_KEY_GEN},
		Template: AttributeMap(aesKeyTemplate),
	}
	aesGenerateKeyStatus, err := cryptoClient.GenerateKey(context.Background(), aesGenerateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKey error: %s", err))
	}

	iv := []byte("0123456789abcdef")
	             
	// Encrypt the seed using the ephemeral key
	encryptSingleRequest := &pb.EncryptSingleRequest{
		Mech:  &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: &pb.Mechanism_ParameterB{ParameterB: iv[:]}},
		Key:   aesGenerateKeyStatus.KeyBytes,
		Plain: secretPlainVal,
	}
	encryptSingleResponse, err := cryptoClient.EncryptSingle(context.Background(), encryptSingleRequest)
	if err != nil {
		panic(fmt.Errorf("Encrypt secret error: %s", err))
	}


	// Uncrypt the ciphered seed to get the key blob 
	unnwrapKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_CLASS:       ep11.CKO_SECRET_KEY,
		ep11.CKA_KEY_TYPE:    ep11.CKK_GENERIC_SECRET,
		ep11.CKA_VALUE_LEN:   secretPlainLen,
		ep11.CKA_WRAP:        false,
		ep11.CKA_UNWRAP:      false,
		ep11.CKA_SIGN:        true,
		ep11.CKA_VERIFY:      true,
		ep11.CKA_DERIVE:      true,
		ep11.CKA_IBM_USE_AS_DATA: true,
		ep11.CKA_EXTRACTABLE: false,
	}

	unwrapRequest := &pb.UnwrapKeyRequest{
		Wrapped:  encryptSingleResponse.Ciphered,
		KeK:      aesGenerateKeyStatus.KeyBytes,
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: &pb.Mechanism_ParameterB{ParameterB: iv[:]}},
		Template: AttributeMap(unnwrapKeyTemplate),
	}

	unWrappedResponse, err := cryptoClient.UnwrapKey(context.Background(), unwrapRequest)
	if err != nil {
		panic(fmt.Errorf("Unwrap key error: %s", err))
	}

	fmt.Println("Master Seed: " +hex.EncodeToString(unWrappedResponse.UnwrappedBytes)+"\n")
}
