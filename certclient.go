package main

import (
	"crypto/tls"
   // "encoding/pem"
	"fmt"
	//"net/http"
	"time"
	"os"
    "sync"
   //"log"
   "io/ioutil"
   "net"
	"crypto/x509"
    
    "crypto/rsa"
    "crypto/dsa"
    "crypto/ecdsa"
    "golang.org/x/crypto/ocsp"    
    "strings"
    )
  
var wg sync.WaitGroup




var cses = map[uint16]string{
0x0005 :"TLS_RSA_WITH_RC4_128_SHA               ",
0x000a :"TLS_RSA_WITH_3DES_EDE_CBC_SHA          ",
0x002f :"TLS_RSA_WITH_AES_128_CBC_SHA           ",
0x0035 :"TLS_RSA_WITH_AES_256_CBC_SHA           ",
0x003c :"TLS_RSA_WITH_AES_128_CBC_SHA256        ",
0x009c :"TLS_RSA_WITH_AES_128_GCM_SHA256        ",
0x009d :"TLS_RSA_WITH_AES_256_GCM_SHA384        ",
0xc007 :"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA       ",
0xc009 :"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA   ",
0xc00a :"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA   ",
0xc011 :"TLS_ECDHE_RSA_WITH_RC4_128_SHA         ",
0xc012 :"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA    ",
0xc013 :"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA     ",
0xc014 :"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA     ",
0xc023 :"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
0xc027 :"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256  ",
0xc02f :"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256  ",
0xc02b :"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
0xc030 :"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384  ",
0xc02c :"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
0xcca8 :"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305   ",
0xcca9 :"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 ",
}

var  protocols = map[string]uint16  {
    "SSL3":0x0300,
    "TLS":0x0301,
    "TLS1.1":0x0302,
    "TLS1.2":0x0303,
}
type PublicKeyAlgorithm int
var  pkalgs = map[int]string  {
    1:"RSA",2:"DSA",3:"ECDSA",
}

func rev_protocols(p uint16) string{
 ov := "unknown";
 for k,v := range protocols{
    if(v == p){ov = k};
 }
 return ov
}


func PubKeyLen (v *x509.Certificate) int{
    defer wg.Done()
     p := int(v.PublicKeyAlgorithm)
     //fmt.Println("protocol",p)
     var rsc int
     switch p {
     case 1:{
        rsc =v.PublicKey.(*rsa.PublicKey).N.BitLen()
      }
     case 2:{
        rsc = v.PublicKey.(*dsa.PublicKey).Y.BitLen()}
     case 3:{
         rsc = v.PublicKey.(*ecdsa.PublicKey).Y.BitLen()
         //rscx:= v.PublicKey.(*ecdsa.PublicKey).X.BitLen()
         //c := v.PublicKey.(*ecdsa.PublicKey).Curve.Params()
         //fmt.Printf("%s (%i)\nX:%s\nY:%s\nP:%s\nN:%s\nB:%s\nGx, Gy:%s %s\n",c.Name,c.BitSize,rscx,rsc,c.P, c.N, 
         //c.B, c.Gx, c.Gy)
         }
     }
     var i int = rsc
     return i
}





func time_defs(nb,na time.Time) string{
    ca := ""
    now := time.Now()
    ca += fmt.Sprintf("TNN:%s\n",now)
    ca += fmt.Sprintf("TNB:%s\n",nb)
    ca += fmt.Sprintf("TNA:%s\n",na)
    ca += fmt.Sprintf("TL:%v\n",(na.Sub(nb)).Hours()/24/365)
    ca += fmt.Sprintf("TOO:%t\n",na.Before(now))
    ca += fmt.Sprintf("TON:%t\n",nb.After(now))
    ca += fmt.Sprintf("TEX:%v\n",na.Sub(now).Hours()/24)
   return ca
}

func get_protocols_2(servername string, rv chan string) {
    var ov string
    defer wg.Done()
    for pname,prot :=range protocols{
        //fmt.Println("doing ",pname)
        now := time.Now()
        
        config := tls.Config{InsecureSkipVerify: true,
        MaxVersion:  prot,
        ServerName: servername,
        }
        connt, err := net.DialTimeout("tcp", servername, time.Second)
        in2sec:= now.Add(time.Second*3)
        conn := tls.Client(connt,&config)
        err = conn.SetDeadline(in2sec)
        err = conn.Handshake() 
        
        //fmt.Println("--->",conn.ConnectionState() )
        if err != nil {
            ov += fmt.Sprintf("ver:%s fail (%s)\n" ,pname,err.Error())
        }else{
        
        defer conn.Close()
        ov += fmt.Sprintf("ver:%s ok\n" ,pname)
    }}
    rv <- ov
}





func get_cert(server string,rv chan string, certpool *x509.CertPool ){
    defer wg.Done()
    var ca string
    var outs string
    config := tls.Config{InsecureSkipVerify: true,
    }
	conn, err := tls.Dial("tcp", server, &config)
	if err != nil {
		//log.Fatalf("client: dial: %s", err)
	}else{
    
	defer conn.Close()
	outs += fmt.Sprintf("client: connected to: %s", conn.RemoteAddr())
	state := conn.ConnectionState()
    ocspr := conn.OCSPResponse()    
    for _, v := range state.PeerCertificates {
        if err == nil{fmt.Sprint(err)}
        if len(ocspr)>0{
            ov, err := ocsp.ParseResponse(ocspr,v)
            if err == nil {
                ca += fmt.Sprintf("\n\nverified: %s end\n\n",ov.Status)
            }
        }
        wg.Add(1)
        ca += fmt.Sprintf("PKL:%d\n",PubKeyLen(v))
        ca += fmt.Sprintf("PKA:%s\n",pkalgs[int(v.PublicKeyAlgorithm)])        
        ca += fmt.Sprintf("sub:%s\n",(v.Subject))
        ca += fmt.Sprintf("SIG:%x\n",v.Signature)
        ca += fmt.Sprintf("SIA:%s\n",v.SignatureAlgorithm)
        ca += fmt.Sprint(time_defs(v.NotBefore,v.NotAfter))
        
        // pemdata := pem.EncodeToMemory(
            // &pem.Block{
            // Type: "CERTIFICATE",
            // Bytes: []byte(v.Raw         ),
                // },
        // )
        
        
        // ca += fmt.Sprintf("IN cert POOL: %s\n", pemdata)
	}
	ca += fmt.Sprintf("vc :%x\n",state.VerifiedChains)
    ca += fmt.Sprintf("ver:%s\n",rev_protocols(state.Version))
    ca += fmt.Sprintf("cs :%s\n",strings.TrimSpace(cses[uint16(state.CipherSuite)]))
    ca += fmt.Sprintf("np :%s\n",state.NegotiatedProtocol)
	}
   rv <- ca
}  



func main() {

    servername := fmt.Sprintf("%s:%s",os.Args[1],os.Args[2])
    certpool := x509.NewCertPool()

    if(len(os.Args)>3){fmt.Println(os.Args[3])
    dat, err := ioutil.ReadFile(os.Args[3])
    if err==nil {certpool.AppendCertsFromPEM([]byte(dat))}
    }
 
    pv := make(chan string)
    cc := make(chan string)
  
    fmt.Print(servername,"\n")
    wg.Add(2)
    go get_protocols_2(servername,pv)
    go get_cert(servername,cc,certpool)
    prots := <-pv
    certs := <-cc
    wg.Wait()
    fmt.Print(prots, certs)
    
}	
