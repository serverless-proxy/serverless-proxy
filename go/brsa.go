// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 RethinkDNS and its authors.

package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/cloudflare/circl/blindsign"
	"github.com/cloudflare/circl/blindsign/blindrsa"
)

const delim = ":"

var fixedmsg []byte = []byte("pip-v0-golang-circl-msg-rsa-pss-384")

type (
	Message []byte
)

type PipKey interface {
	Blind() (string, error)
	Finalize(string) bool
}

//	{
//	  kty: "RSA",
//	  alg: "PS384",
//	  n: "lSFviqAqSHpPOtVgm7...",
//	  e: "AQAB",
//	  key_ops: [ "verify" ],
//	  ext: true
//	}
type pubKeyJwk struct {
	Kty    string   `json:"kty"`           // key type: RSA
	Alg    string   `json:"alg,omitempty"` // algorithm: PS384
	N      string   `json:"n"`             // modulus
	E      string   `json:"e"`             // exponent
	KeyOps []string `json:"key_ops"`       // key operations: verify
	Ext    bool     `json:"ext"`           // extractable: true
}

type pipkey struct {
	pubkey      *rsa.PublicKey
	rsavp1      *blindrsa.RSAVerifier
	rsavp1state blindsign.VerifierState
	blindMsg    []byte
	hasher      crypto.Hash
	when        time.Time
}

func NewPipKey(pubjwk string, existingState string) (PipKey, error) {
	jwk := &pubKeyJwk{}
	pubbytes := []byte(pubjwk)
	json.Unmarshal(pubbytes, jwk)
	// base64 decode modulus and exponent into a big.Int
	n, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}
	bn := big.NewInt(0)
	bn.SetBytes(n)
	e, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}
	be := big.NewInt(0)
	be.SetBytes(e)
	// create rsa.PublicKey
	pub := &rsa.PublicKey{
		N: bn,
		E: int(be.Int64()),
	}
	hfn := crypto.SHA384
	v := blindrsa.NewRSAVerifier(pub, hfn)
	k := &pipkey{
		pubkey: pub,
		rsavp1: &v,
		hasher: hfn,
		when:   time.Now(),
	}
	if existingState != "" {
		// blindMsg + delim + r + delim + salt
		parts := strings.Split(existingState, delim)
		k.blindMsg = hex2byte(parts[0])
		r := hex2byte(parts[1])
		salt := hex2byte(parts[2])
		if bmsg, state, err := k.rsavp1.FixedBlind(fixedmsg, r, salt); err != nil {
			return nil, err
		} else {
			k.rsavp1state = state
			if !bytes.Equal(k.blindMsg, bmsg) {
				return nil, blindrsa.ErrInvalidBlind
			}
		}
	}
	return k, nil
}

func (k *pipkey) Blind() (string, error) {
	if k.rsavp1state != nil {
		fmt.Println("pipkey: blind: already blinded")
		return "", blindrsa.ErrInvalidBlind
	}
	// blindMsg, state, err := k.rsavp1.Blind(rand.Reader, fixedmsg)
	one := big.NewInt(1)
	blindMsg, state, err := k.rsavp1.FixedBlind(fixedmsg, one.Bytes(), nil)
	if err != nil {
		fmt.Printf("pipkey: blind: %v", err)
		return "", err
	}
	r := state.CopyBlind()
	bigr := new(big.Int).SetBytes(r)
	bigrinv := new(big.Int).ModInverse(bigr, k.pubkey.N)
	salt := state.CopySalt()
	k.rsavp1state = state
	return byte2hex(blindMsg) + delim + byte2hex(r) + delim + byte2hex(bigrinv.Bytes()) + delim + byte2hex(salt), nil
}

func (k *pipkey) Finalize(blindSig string) bool {
	blindsigbytes := hex2byte(blindSig)
	sigbytes, err := k.rsavp1state.Finalize(blindsigbytes)
	if err != nil {
		fmt.Printf("pipkey: finalize: %v", err)
		return false
	}
	return k.rsavp1.Verify(fixedmsg, sigbytes) == nil
}

func hex2byte(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

func byte2hex(b []byte) string {
	return hex.EncodeToString(b)
}

func testrsa() {
	pkjwk := "{\"kty\":\"RSA\",\"alg\":\"PS384\",\"n\":\"vRJS-stmaRwFsgmbtugnZLPcGz-80gnbYdCuhju4CwbuGeQk2JI1Qkivcy50TFgO5z7jz38ighp_Hr2kvOOEWvo_l_J_Ix3mpw9RBDZF6ocNRYuoS9R_SoeMgrx-VQWC1VSqqbbT7A5526an4Kmsrnes1MyroK052CT4QYPUT_wbICmv85uqEuyD7q6X-HpHvHBTiTRQtcfxHJUrXebInCU6cg1VtcJsDoYczRVL1i9_7z5POMyjAx1v-sSR_16r6H1NLghR6fpUwm-HmbKSPwqrN5NA8Q-94spj4zp_4PoAEQi2NRnjJSQQxPBeH8RRAfdO7HwnhDm7hXXgocTj_w\",\"e\":\"AQAB\",\"key_ops\":[\"verify\"],\"ext\":true}"
	// skjwk := "{\"kty\":\"RSA\",\"alg\":\"PS384\",\"n\":\"vRJS-stmaRwFsgmbtugnZLPcGz-80gnbYdCuhju4CwbuGeQk2JI1Qkivcy50TFgO5z7jz38ighp_Hr2kvOOEWvo_l_J_Ix3mpw9RBDZF6ocNRYuoS9R_SoeMgrx-VQWC1VSqqbbT7A5526an4Kmsrnes1MyroK052CT4QYPUT_wbICmv85uqEuyD7q6X-HpHvHBTiTRQtcfxHJUrXebInCU6cg1VtcJsDoYczRVL1i9_7z5POMyjAx1v-sSR_16r6H1NLghR6fpUwm-HmbKSPwqrN5NA8Q-94spj4zp_4PoAEQi2NRnjJSQQxPBeH8RRAfdO7HwnhDm7hXXgocTj_w\",\"e\":\"AQAB\",\"d\":\"bc3vjSGFh3OzxxMXcOFgx3ZBVT3t_hmlZChawzB5kUXkD_tUfsZi0ez-oCkRd6kIdroqeb4_H0oeG49N1jlYC7IcLrWxqoZaBxm5FnYiorLuPT5_bhKqHnGcY-zufZgmxJhYSRoZ95TspmkiRDKmS-jK4gc_gaA44NOPrhTOv-gNcI5u15vAr0Ei2KWD4v86f-F1u44xy2-kEOtoHBr6PrFhp7cPKrO0byNIwfIElXSa3Ws347cpPeawU33XnNtMmNz0rdZMsjbZravILIjXgwhTV1hg9WIg6l6Dq6U6iEI8owoW-EqSr3oVy5zRnR2lGKj4IzSU-g4BWWyunJFY0Q\",\"p\":\"1FDqhuHh3zoepa22olf4SLYdey-D9iimynt1n4vyijIdaoOnuWEFdth9AlCm6u3EYQYX9HkQQxsM6bjo1Bwh8rQzeBkj34mS5b2thor1cGxgXjYVC7DPW2rf06VkFB5ELl9yPVFhuYGPw5ekuXPs7ZTi2pW71U3Akgo3PmHV2tc\",\"q\":\"4_kTrIJjxWDp42Fn53jRDrj5cDsnM1j_7XYBj68lbdQKz0jucHxLe1mCt8C-DT1LCsXWaBnBwzIqdWMapJz6PzTGk6AIwdI371_65poWwaC7b65Jd5CNnG_V3EPUx1GnWGoeYO3Fa3rayeE9bfm6K0Suzhp-l89DIr7qSff-Axk\",\"dp\":\"ByWKH2wvDDKKoY0NXr2TT-9BYsogqQKJSruJJAuz6E7ziohP9v97DZsP6ioI1FOYjqOD3ujMUVXxw1REEg-4XNEQAnTmLjoVRcJyutqmlFgxjjpHzxLuh-c7DYa9raevJ9hyofnBTls8GZtbIhry2LRwRmdP4UgyuTe60FC-wBU\",\"dq\":\"c8lgCrA3CFrOsCQa59_fHoEof64rnNLJOcxDwryMYBngW6OJJyyaEc5GrBmC7aqB4LjWywy58vAZzIFHWPA50bx2VyhjCj5BFp1DC7ibckC2smRtAAM1SY0rq7Hv8kQwoKFVSJm7OXmugfaagq7htXQu7JNcVLJ6QL2CtYr1QpE\",\"qi\":\"dUR-9jxBR70IqvWvhM3hZMi5n02HD1kUTp-MG04l0txGrGOB6_1VgFWxlyDWQfeSDLocWoc4W0VZX638BmhkJKdpAId7LbwprRzZopgzH6F1PAxzXPFBFwDU90mQ2fZ8j4rgQMJshvvf207Tqxm0tMzmnwr06_W7mqxTiiisJmk\",\"key_ops\":[\"sign\"],\"ext\":true}"
	blindmsgs := ""
	// blindmsg:r:salt
	// blindmsgs := "6d65ff115c3805cc0466219179e02f6910add8d865e6bdb9e99eeeb842e82640e38fe20667e2a04ea8705eac04f399605857e72a5e922f9a59ead6bab43208211826ebf72f2dff447c645eae35a1f04d2108d1ba96b658fc453ec331a8628d8057896809e53ff9bf8f35230a268a543ef575ef82996dd1320cca3bb8b87d20141b0321ff184c0df0ecb5a1c52da74f67220479cef71e32430bd42aceb52ae279d90dcbf74abc79a5bfcf7892d7828f2df4af6ccf7255b7461640312729f8bb0cc843f2663b1eae77e72cad7d2b9e0b808a7f58b0d1e1d83906ed161f24a39990b65a273838892ae66013633195e5c8b103b7a6032b5b70a403ebb6ebb342d436:33401c389247c0400b5447b32cc2ee32b5731e286d187576866d67bf3da99f404e86eb26fcd55c14e67f5cf1a88eb76cda5d20c1b3b253e61cbf008b586b9b2ba4e410346dff3817ec447c3ddcb63ea56fd1522df4701aae2e9c2d616bd41892dfde4fe27c5062e4fdae2bd8609b1b1f7d5c369cf494e7e3b15f71d53f8acdc52898de1a6ff85bd7b9dfee778292f5ca823f8045a771769812bf5bf9b25d08fa8b6855d5a8788272141ec4fe0676a84d149ab51e1b6c594552723a6c9254c3859fd5b8793481b33d1fdff9456878dd7f052e929a1ed1d0fc7ed11a86fd5be3d65a399edb3034bd4f8e7c582344cfa69d3dba23fad21f5be97b739f1d40bc6c96:48ff3c4adbba2c240d6503e63d1991c72e141f16885a7b7d95f12456dcdafc50425055ef5f55673e44128a840b2e9fbe"
	bsig := ""
	// bsig := "063d0c1efd129c9ad6b3184f944c1c3cc4d2177b4c6c34040823293cf058f1ef5e8fc1b0dd5654e38344d870a73f9aef95da3dbd4f97b466b1b8d88a5720788d6d9e4bd55e75644cbf25bab1380c6006c0560a79eca2f1fcbcea5908a894c9f6317bf5030925f8c6a84876acd6af0481ae4cfe6a73b4f12ef1bdda0eab00a8d230941f8c5b7de7b7861826f7d6309d99f1ef74b1fc3cd482d6f2f55d5e4830180b204b2a1d0496148450a825f6a510d1837fa69d850cdd96e1d2a371eebd1b3b31309504d7377adfa57cc9688e8b08aff0f46cde54bc660fd5ccba75a371fe8d6ba216a926c3c1ba59fabd3ccd66475aea89440eee617079d9e26e318b3e482e"
	pk, err := NewPipKey(pkjwk, blindmsgs)
	if err != nil {
		fmt.Printf("pipkey: setup: %v", err)
		return
	}
	if len(blindmsgs) <= 0 {
		blindMsgs, err := pk.Blind()
		if err != nil {
			fmt.Printf("pipkey: blind: %v", err)
			return
		}
		fmt.Printf("pipkey: blindMsgs: %s\n", blindMsgs)
	}
	if len(bsig) > 0 {
		ok := pk.Finalize(bsig)
		fmt.Printf("\npipkey: ok: %t\n", ok)
	}
}
