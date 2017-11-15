package main

import (
	"bufio"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var wg sync.WaitGroup

var programTimeStart time.Time

var cses = map[uint16]string{
	0x0005: "TLS_RSA_WITH_RC4_128_SHA               ",
	0x000a: "TLS_RSA_WITH_3DES_EDE_CBC_SHA          ",
	0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA           ",
	0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA           ",
	0x003c: "TLS_RSA_WITH_AES_128_CBC_SHA256        ",
	0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256        ",
	0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384        ",
	0xc007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA       ",
	0xc009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA   ",
	0xc00a: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA   ",
	0xc011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA         ",
	0xc012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA    ",
	0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA     ",
	0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA     ",
	0xc023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	0xc027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256  ",
	0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256  ",
	0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384  ",
	0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305   ",
	0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 ",
}

var protocols = map[string]uint16{
	"SSL3":   0x0300,
	"TLS":    0x0301,
	"TLS1.1": 0x0302,
	"TLS1.2": 0x0303,
}

var pkalgs = map[int]string{
	1: "RSA", 2: "DSA", 3: "ECDSA",
}

func revProtocols(p uint16) string {
	ov := "unknown"
	for k, v := range protocols {
		if v == p {
			ov = k
		}
	}
	return ov
}

func pubKeyLen(v *x509.Certificate) int {
	p := int(v.PublicKeyAlgorithm)
	var rsc int
	switch p {
	case 1:
		{
			rsc = v.PublicKey.(*rsa.PublicKey).N.BitLen()
		}
	case 2:
		{
			rsc = v.PublicKey.(*dsa.PublicKey).Y.BitLen()
		}
	case 3:
		{
			c := v.PublicKey.(*ecdsa.PublicKey).Curve.Params()
			fmt.Printf(" ECDSA parameters:%s (%d)\n", c.Name, c.BitSize)
		}
	}
	i := int(rsc)
	return i
}

func timeDefs(nb, na time.Time) string {
	ca := ""
	now := time.Now()
	ca += fmt.Sprintf(" TIME/NOW:%s\n", now)
	ca += fmt.Sprintf(" TIME/NOT BEFORE:%s\n", nb)
	ca += fmt.Sprintf(" TIME/NOT AFTER:%s\n", na)
	ca += fmt.Sprintf(" TIME/LIFESPAN:%4.1f YEARS\n", (na.Sub(nb)).Hours()/24/365)
	ca += fmt.Sprintf(" TIME/TOO OLD:%t\n", na.Before(now))
	ca += fmt.Sprintf(" TIME/TOO NEW:%t\n", nb.After(now))
	ca += fmt.Sprintf(" TIME/EXPIRE IN:%6.0f DAYS\n", na.Sub(now).Hours()/24)
	return ca
}

func httpSpecific(server string, servername string) string {

	client := &http.Client{
		Transport: &http.Transport{
			DisableCompression: true,
			TLSClientConfig: &tls.Config{
				ServerName:         servername,
				InsecureSkipVerify: true,
			},
			TLSHandshakeTimeout: 3 * time.Second,
		},
	}

	//resp, err := client.Head("https://"+server)
	req, err := http.NewRequest("OPTIONS", "https://"+server, nil)

	if err != nil {
		fmt.Printf("%v\n", err.Error())
	}
	req.Header.Add("Accept-Encoding", "deflate,gzip,compress")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("ERR:%v\n", err.Error())
	} else {
		defer resp.Body.Close()

		fmt.Printf("RESP: %+v\n", resp)
		fmt.Printf("RESP STS: %+v\n", resp.Header["Strict-Transport-Security"])
		fmt.Printf("RESP COM: %+v\n", resp.Header["Content-Encoding"])
		fmt.Printf("RESP TRA: %+v\n", resp.Header["Transfer-Encoding"])
		fmt.Printf("RESP Compression: %t\n", resp.Uncompressed)
		//cnt, err := ioutil.ReadAll(resp.Body)
		//fmt.Printf("RESP BODY: %s\n",cnt)
	}
	return ""

}

func getProtocols(server string, rv chan string) {
	defer wg.Done()
	var ov string
	servername := strings.Split(server, ":")[0]
	for pname, prot := range protocols {
		//fmt.Println("doing ",pname)
		now := time.Now()
		in2sec := now.Add(time.Second * 1)
		config := tls.Config{InsecureSkipVerify: true,
			MaxVersion: prot,
			ServerName: servername,
		}
		//fmt.Println("connecting")
		connt, err := net.DialTimeout("tcp", server, time.Second)

		if err != nil {
			ov += fmt.Sprintf("PROTOCOL VERSION:%s fail (%s)\n", pname, err.Error())
			continue
		}
		defer connt.Close()
		conn := tls.Client(connt, &config)
		err = conn.SetDeadline(in2sec)
		err = conn.Handshake()
		if err != nil {
			ov += fmt.Sprintf("PROTOCOL VERSION:%s fail\n", pname)
			fmt.Printf("INFO:failed %s connection: %s\n", pname, err.Error())
			continue
		} else {

			defer conn.Close()
			ov += fmt.Sprintf("PROTOCOL VERSION:%s ok\n", pname)
		}
	}
	rv <- ov
}

func enumCipherSuites(server string, service string) string {

	var passv, failv string
	servername := strings.Split(server, ":")[0]
	fmt.Println("TUKEj", servername, server)
	var clist []uint16
	clist = append(clist, uint16(0))
	for cs, cname := range cses {
		clist[0] = cs
		//fmt.Println("doing ",pname)
		//now := time.Now()
		//in2sec:= now.Add(time.Second*1)
		config := tls.Config{InsecureSkipVerify: true,
			CipherSuites: clist,
			ServerName:   servername,
		}
		//fmt.Println("connecting")
		conn, err := tls.Dial("tcp", server, &config)
		//fmt.Println((conn.VerifyHostname(server)).Error())
		if err != nil {
			failv += fmt.Sprintf("ERR: %s %s \n", err.Error(), cname)
		} else {

			conn.Close()
			passv += fmt.Sprintf("PROTOCOL VERSION:%s ok\n", cname)
		}
	}
	return passv + failv
}

func getCert(server string, rv chan string, certpool *x509.CertPool) {
	defer wg.Done()

	secureRenegotiation := regexp.MustCompile("secureRenegotiation:(true|false)")
	//fmt.Printf("%q\n", re.FindAllStringSubmatch("-ab-", -1))

	var ca string
	var outs string
	servername := strings.Split(server, ":")[0]
	config := tls.Config{InsecureSkipVerify: true,
		ServerName: servername,
	}
	conn, err := tls.Dial("tcp", server, &config)
	//fmt.Println((conn.VerifyHostname(server)).Error())
	if err != nil {
		rv <- "ERR:Could not make SSL/TLS connection"
	} else {

		defer conn.Close()
		outs += fmt.Sprintf("INFO: connected to: %s\n", conn.RemoteAddr())
		state := conn.ConnectionState()
		mr := fmt.Sprintf("%+v", conn)
		//fmt.Printf("TUTEJ:%s" ,(mr))
		ocspr := state.OCSPResponse
		ca += outs
		ca += fmt.Sprintf("OCSP RESPONSE LEN:%d\n", len(ocspr))

		//ca += fmt.Sprintf("STATE:%+v\n",state)
		ca += fmt.Sprintf("CERTIFICATE CHAIN LEN:%d\n", len(state.PeerCertificates))
		//ca += fmt.Sprintf("vc :%x\n",state.VerifiedChains)
		ca += fmt.Sprintf("NEGOTIATED PROTOCOL VERSION:%s\n", revProtocols(state.Version))
		ca += fmt.Sprintf("CIPHER SUITE :%s\n", strings.TrimSpace(cses[uint16(state.CipherSuite)]))
		ca += fmt.Sprintf("SCT ATTACHED :%t\n", len(state.SignedCertificateTimestamps) > 0)
		//ca += fmt.Sprintf("np :%s\n",state.NegotiatedProtocol)
		i := 0
		for _, v := range state.PeerCertificates {
			// if err == nil{fmt.Sprint(err)}
			// if len(ocspr)>0{
			// ov, err := ocsp.ParseResponse(ocspr,v)
			// if err == nil {
			// ca += fmt.Sprintf("\n\nverified: %s end\n\n",ov.Status)
			// }
			// }
			//  wg.Add(1)
			ca += fmt.Sprintf("SUBJECT (%d):%s\n", i, v.Subject.CommonName)
			i++
			ca += fmt.Sprintf(" ISSUER:%s\n", (v.Issuer.CommonName))
			ca += fmt.Sprintf(" PUBLIC KEY LENGTH:%d\n", pubKeyLen(v))
			ca += fmt.Sprintf(" PUBLIC KEY ALGORITHM:%s\n", pkalgs[int(v.PublicKeyAlgorithm)])

			//ca += fmt.Sprintf(" EXTENSIONS:%+v\n", (v.Extensions))
			//ca += fmt.Sprintf("SIG:%x\n",v.Signature)
			ca += fmt.Sprintf(" SIGNATURE ALGORITHM:%s\n", v.SignatureAlgorithm)
			ca += fmt.Sprintf(" OCSP SERVER:%s\n", v.OCSPServer)
			ca += fmt.Sprintf(" EXT:%s\n", secureRenegotiation.FindString(mr))
			ca += fmt.Sprintf(" CRLDistributionPoints :%s\n", v.CRLDistributionPoints)
			ca += fmt.Sprint(timeDefs(v.NotBefore, v.NotAfter))

			pemdata := pem.EncodeToMemory(
				&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: []byte(v.Raw),
				},
			)

			if showCertsPtr {
				ca += fmt.Sprintf(" PEM_CERT_LEN: %s\n", (pemdata))
			}
		}

	}
	rv <- ca
}

func printAtExit() {
	fmt.Println(time.Now().Sub(programTimeStart) / time.Millisecond)
	if !unattended {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("press enter to end")
		reader.ReadString('\n')
		//fmt.Println(text)

	}

}

var unattended bool
var showCertsPtr bool

func main() {
	defer printAtExit()

	unattendedPtr := flag.Bool("u", false, "unattended run")
	tryCSPtr := flag.Bool("t", false, "try ciphersuites")
	detectProtocolsPtr := flag.Bool("d", false, "detect protocols")
	httpSpecificPtr := flag.Bool("http", true, "check http specific opts")
	flag.BoolVar(&showCertsPtr, "s", false, "show certificates")
	//showCertsPtr =

	flag.Parse()
	programTimeStart = time.Now()
	unattended = *unattendedPtr
	server := ""
	endpoint := ""
	remainingArgs := flag.Args()
	if len(remainingArgs) == 0 {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("provide server_address:port\n")
		text, _ := reader.ReadString('\n')
		fmt.Println(text)
		server = strings.TrimSpace(strings.Split(text, ":")[0])
		endpoint = strings.TrimSpace(text)
	} else {
		port := "443"
		if len(remainingArgs) > 1 {
			port = remainingArgs[1]
		}
		endpoint = fmt.Sprintf("%s:%s", remainingArgs[0], port)
		server = fmt.Sprintf("%s", remainingArgs[0])

	}
	certpool := x509.NewCertPool()
	if *httpSpecificPtr {
		httpSpecific(endpoint, server)
	}

	if *tryCSPtr {
		fmt.Println(enumCipherSuites(endpoint, server))
	}
	if len(remainingArgs) > 3 {
		fmt.Println(remainingArgs[3])
		dat, err := ioutil.ReadFile(remainingArgs[3])
		if err == nil {
			certpool.AppendCertsFromPEM([]byte(dat))
		}

		//b,_ := pem.Decode([]byte(dat))
		//cert, _:= x509.ParseCertificate(b.Bytes)
		//fmt.Printf("---> %s, %x",cert.Subject,cert.Signature)
	}
	//
	cc := make(chan string)

	fmt.Print("TARGET SERVER:", endpoint, "\n")
	wg.Add(1)
	go getCert(endpoint, cc, certpool)
	certs := <-cc

	if *detectProtocolsPtr {
		pv := make(chan string)
		wg.Add(1)
		go getProtocols(endpoint, pv)
		prots := <-pv
		defer fmt.Print(prots)
	}

	//
	wg.Wait()
	fmt.Print(certs)

}
