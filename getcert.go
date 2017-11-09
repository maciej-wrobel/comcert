package main

import (
	"crypto/tls"
	"crypto/x509"
    "crypto/rsa"
     "crypto/dsa"
     "crypto/ecdsa"
     "golang.org/x/crypto/ocsp"
     
	"fmt"
	"log"
    "os"
    "sync"
)
var wg sync.WaitGroup
func PubKeyLen (v *x509.Certificate) int{
defer wg.Done()
 p := (v.PublicKeyAlgorithm)
 fmt.Println("protocol",p)
 var rsc int
 switch p {
 case 1:{
    rsc =v.PublicKey.(*rsa.PublicKey).N.BitLen()
  }
 case 2:{
 rsc = v.PublicKey.(*dsa.PublicKey).Y.BitLen()}
 case 3:{
 rsc = v.PublicKey.(*ecdsa.PublicKey).Y.BitLen()
 rscx:= v.PublicKey.(*ecdsa.PublicKey).X.BitLen()
 c := v.PublicKey.(*ecdsa.PublicKey).Curve.Params()
 fmt.Printf("%s (%i)\nX:%s\nY:%s\nP:%s\nN:%s\nB:%s\nGx, Gy:%s %s\n",c.Name,c.BitSize,rscx,rsc,c.P, c.N, 
 c.B, c.Gx, c.Gy)
 }
 }
 
 var i int = rsc
 return i
}


func main() {

	config := tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", os.Args[1], &config)
	if err != nil {
		log.Fatalf("client: dial: %s", err)
	}
	defer conn.Close()
	fmt.Println("client: connected to: ", conn.RemoteAddr())

	state := conn.ConnectionState()
    ocspr := conn.OCSPResponse()
    for _, v := range state.PeerCertificates {
    if err == nil{fmt.Println(err)}
    if len(ocspr)>0{
    //fmt.Println("OCSP response:",ocspr,"end")
    ov, err := ocsp.ParseResponse(ocspr,v)
    if err == nil {fmt.Println("\n\nverified:",ov.Status,err,"end\n\n")}
    }
	
    wg.Add(1)
    fmt.Println(PubKeyLen(v))
	fmt.Println(v.Subject)
    fmt.Println(v.SignatureAlgorithm)
    //fmt.Printf("%+v",v)
	}
	fmt.Println(state.VerifiedChains)
    fmt.Printf("%x\n",state.Version)
    fmt.Printf("%x\n",state.CipherSuite)
    fmt.Printf("%x\n",state.NegotiatedProtocol)
    wg.Wait()
    fmt.Println("exit\n")
}