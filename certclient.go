package main

import (
	"crypto/tls"
    "encoding/pem"
	"fmt"
	//"net/http"
	"time"
	"os"
    "sync"
    //"log"
    "io/ioutil"
    "net"
	"crypto/x509"
 //"encoding/json"    
    "crypto/rsa"
    "crypto/dsa"
    "crypto/ecdsa"
    //"golang.org/x/crypto/ocsp"    
    "strings"
    "regexp"
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
    //defer wg.Done()
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
    ca += fmt.Sprintf(" TIME/NOW:%s\n",now)
    ca += fmt.Sprintf(" TIME/NOT BEFORE:%s\n",nb)
    ca += fmt.Sprintf(" TIME/NOT AFTER:%s\n",na)
    ca += fmt.Sprintf(" TIME/LIFESPAN:%4.1f YEARS\n",(na.Sub(nb)).Hours()/24/365)
    ca += fmt.Sprintf(" TIME/TOO OLD:%t\n",na.Before(now))
    ca += fmt.Sprintf(" TIME/TOO NEW:%t\n",nb.After(now))
    ca += fmt.Sprintf(" TIME/EXPIRE IN:%6.0f DAYS\n",na.Sub(now).Hours()/24)
   return ca
}

func get_protocols_2(server string, rv chan string) {
    defer wg.Done()
    var ov string
    servername := strings.Split(server,":")[0]
    for pname,prot :=range protocols{
        //fmt.Println("doing ",pname)
        now := time.Now()
        in2sec:= now.Add(time.Second*1)
        config := tls.Config{InsecureSkipVerify: true,
        MaxVersion:  prot,
        ServerName: servername,
        }
        //fmt.Println("connecting")
        connt, err := net.DialTimeout("tcp", server, time.Second)
        
        if err != nil {
            ov += fmt.Sprintf("PROTOCOL VERSION:%s fail (%s)\n" ,pname,err.Error())
            continue
        }
        defer connt.Close()
        conn := tls.Client(connt,&config)
        err = conn.SetDeadline(in2sec)
        err = conn.Handshake()
        if err != nil {
            ov += fmt.Sprintf("PROTOCOL VERSION:%s fail\n" ,pname)
            fmt.Printf("INFO:failed %s connection: %s\n",pname,err.Error())
            continue
        }else{
        
        defer conn.Close()
        ov += fmt.Sprintf("PROTOCOL VERSION:%s ok\n" ,pname)
    }}
    rv <- ov
}





func get_cert(server string,rv chan string, certpool *x509.CertPool ){
    defer wg.Done()
    
    secureRenegotiation := regexp.MustCompile("secureRenegotiation:(true|false)")
	//fmt.Printf("%q\n", re.FindAllStringSubmatch("-ab-", -1))
    
    var ca string
    var outs string
    servername := strings.Split(server,":")[0]
    config := tls.Config{InsecureSkipVerify: true,
    ServerName:servername,
    }
	conn, err := tls.Dial("tcp", server, &config)
    fmt.Println((conn.VerifyHostname(server)).Error())
	if err != nil {
		rv <- "ERR:Could not make SSL/TLS connection"
	}else{
    
	defer conn.Close()
	outs += fmt.Sprintf("INFO: connected to: %s\n", conn.RemoteAddr())
	state := conn.ConnectionState()
    mr := fmt.Sprintf("%+v",conn)
    //fmt.Printf("TUTEJ:%s" ,(mr))
    ocspr := state.OCSPResponse                   
    ca+= outs
    ca += fmt.Sprintf("OCSP RESPONSE LEN:%d\n",len(ocspr))    
    
    //ca += fmt.Sprintf("STATE:%+v\n",state)   
    ca += fmt.Sprintf("CERTIFICATE CHAIN LEN:%d\n",len(state.PeerCertificates))
	//ca += fmt.Sprintf("vc :%x\n",state.VerifiedChains)
    ca += fmt.Sprintf("NEGOTIATED PROTOCOL VERSION:%s\n",rev_protocols(state.Version))
    ca += fmt.Sprintf("CIPHER SUITE :%s\n",strings.TrimSpace(cses[uint16(state.CipherSuite)]))
    //ca += fmt.Sprintf("np :%s\n",state.NegotiatedProtocol)    
    i := 0;
    for _, v := range state.PeerCertificates {
        // if err == nil{fmt.Sprint(err)}
        // if len(ocspr)>0{
            // ov, err := ocsp.ParseResponse(ocspr,v)
            // if err == nil {
                // ca += fmt.Sprintf("\n\nverified: %s end\n\n",ov.Status)
            // }
        // }
      //  wg.Add(1)
        ca += fmt.Sprintf("SUBJECT (%d):%s\n",i,v.Subject.CommonName)
        i += 1
        ca += fmt.Sprintf(" ISSUER:%s\n",(v.Issuer.CommonName))
        ca += fmt.Sprintf(" PUBLIC KEY LENGTH:%d\n",PubKeyLen(v))
        ca += fmt.Sprintf(" PUBLIC KEY ALGORITHM:%s\n",pkalgs[int(v.PublicKeyAlgorithm)])        
        
        //ca += fmt.Sprintf("ISSUER SN:%+v\n",(v.Extensions))
        //ca += fmt.Sprintf("SIG:%x\n",v.Signature)
        ca += fmt.Sprintf(" SIGNATURE ALGORITHM:%s\n",v.SignatureAlgorithm)
         ca += fmt.Sprintf(" OCSP SERVER:%s\n",v.OCSPServer)
         ca += fmt.Sprintf(" EXT:%s\n",secureRenegotiation.FindString(mr))
        ca += fmt.Sprint(time_defs(v.NotBefore,v.NotAfter))
        
        pemdata := pem.EncodeToMemory(
            &pem.Block{
            Type: "CERTIFICATE",
            Bytes: []byte(v.Raw),
                },
        )
        
        
        ca += fmt.Sprintf(" PEM_CERT_LEN: %d\n", len(pemdata))

	}

	}
   rv <- ca
}  



func main() {

    servername := fmt.Sprintf("%s:%s",os.Args[1],os.Args[2])
    certpool := x509.NewCertPool()

    if(len(os.Args)>3){fmt.Println(os.Args[3])
    dat, err := ioutil.ReadFile(os.Args[3])
        if err==nil {certpool.AppendCertsFromPEM([]byte(dat))}
    
    //b,_ := pem.Decode([]byte(dat))
    //cert, _:= x509.ParseCertificate(b.Bytes)
    //fmt.Printf("---> %s, %x",cert.Subject,cert.Signature)
    }
    pv := make(chan string)
    cc := make(chan string)
  
    fmt.Print("TARGET SERVER:",servername,"\n")
    wg.Add(1)
    wg.Add(1)
    go get_protocols_2(servername,pv)
    
    
    
    
    go get_cert(servername,cc,certpool)
    certs := <-cc
    prots := <-pv
    wg.Wait()
    fmt.Print(prots, certs)
    
}	
