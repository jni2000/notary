// A CryptoService client wrapper around a remote wrapper service.

package client

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
	"os"
	"os/exec"
        "bufio"
	"log"
        "encoding/json"
	"encoding/hex"
	"strings"

	"github.com/theupdateframework/notary"
	pb "github.com/theupdateframework/notary/proto"
	"github.com/theupdateframework/notary/tuf/data"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	// "github.com/go-resty/resty/v2"
)

// RemotePrivateKey is a key that is on a remote service, so no private
// key bytes are available
type RemotePrivateKey struct {
	data.PublicKey
	sClient pb.SignerClient
}

// RemoteSigner wraps a RemotePrivateKey and implements the crypto.Signer
// interface
type RemoteSigner struct {
	RemotePrivateKey
}

// CommScope signed signing log
type CommScopeSigningLog struct {
	Title string
	IpAddr []string	
	MacAddr []string
	TimeStamp string
	NotaryKeyId string
	NotarySignature string
	Subject string
	CsKeyId string
	CsCaId	string
	Signature string
}

// Public method of a crypto.Signer needs to return a crypto public key.
func (rs *RemoteSigner) Public() crypto.PublicKey {
	publicKey, err := x509.ParsePKIXPublicKey(rs.RemotePrivateKey.Public())
	if err != nil {
		return nil
	}

	return publicKey
}

// NewRemotePrivateKey returns RemotePrivateKey, a data.PrivateKey that is only
// good for signing. (You can't get the private bytes out for instance.)
func NewRemotePrivateKey(pubKey data.PublicKey, sClient pb.SignerClient) *RemotePrivateKey {
	return &RemotePrivateKey{
		PublicKey: pubKey,
		sClient:   sClient,
	}
}

// Private returns nil bytes
func (pk *RemotePrivateKey) Private() []byte {
	return nil
}

func check(e error) {
    if e != nil {
        panic(e)
    }
}

func getMacAddr() ([]string, error) {
     ifas, err := net.Interfaces()
     if err != nil {
         return nil, err
     }
     var as []string
     for _, ifa := range ifas {
         a := ifa.HardwareAddr.String()
         if a != "" {
             as = append(as, a)
         }
     }
     return as, nil
}

// Sign calls a remote service to sign a message.
func (pk *RemotePrivateKey) Sign(rand io.Reader, msg []byte,
	opts crypto.SignerOpts) ([]byte, error) {

	keyID := pb.KeyID{ID: pk.ID()}
	sr := &pb.SignatureRequest{
		Content: msg,
		KeyID:   &keyID,
	}

        sig, err := pk.sClient.Sign(context.Background(), sr)
        if err != nil {
                return nil, err
        }

	// invoking CommScope PRiSM RESTful API call to sign 
	signRec := CommScopeSigningLog{Title: "CommScope signature attestation record"}

	fmt.Println("invoking CommScope PKI signning service.....")
	signRec.Subject = string(msg)
	signRec.NotarySignature = hex.EncodeToString(sig.Content)

	// locate the current working directory
	// directory , err0 := os.Getwd() 
	// if err0 != nil {
	//	fmt.Println(err0) //print the error if obtained
	// }
	// fmt.Println("Current working directory:", directory) //print the required directory
	
	//
	// run curl as an interim solution
	//
	// if _, err = os.Stat("PRiSM/PRiSMRESTClient_COMM.GEN.PKICTest.210910.1-2.pfx"); err == nil {
	//	fmt.Println("file PRiSM/PRiSMRESTClient_COMM.GEN.PKICTest.210910.1-2.pfx found")
	// } else {
	//	fmt.Println("file PRiSM/PRiSMRESTClient_COMM.GEN.PKICTest.210910.1-2.pfx NOT found")
	// }
	// if _, err = os.Stat("PRiSM/ArrisPKICenterRootandSubCA.cer"); err == nil {
        //	fmt.Println("file  PRiSM/ArrisPKICenterRootandSubCA.cer found")
        // } else {
        //	fmt.Println("PRiSM/ArrisPKICenterRootandSubCA.cer NOT found")
        // }
	signRec.CsKeyId = "PRiSMRESTClient_COMM.GEN.PKICTest.210910.1"
	signRec.CsCaId ="ArrisPKICenterRootandSubCA"

	// payload := `{"clientSystemID":"testsystemID","clientUserID":"COMM.GEN.PKICTest.210910.1","clientSite":"test site","configPath":"/ARRIS/Demonstration/Demonstration/PKCS1","hashAlgo":"sha256","hash":"6dd87887b3615b455071cee8a5d5d82270b047a4ba91341daa2058778c59439e"}`
	payload1 := `{"clientSystemID":"testsystemID","clientUserID":"COMM.GEN.PKICTest.210910.1","clientSite":"test site","configPath":"/ARRIS/Demonstration/Demonstration/PKCS1","hashAlgo":"sha256","hash":"`
	// payload2 := `6dd87887b3615b455071cee8a5d5d82270b047a4ba91341daa2058778c59439e`
	payload2 := hex.EncodeToString(sig.Content)[:64]
	payload3 := `"}`
	payload := payload1+payload2+payload3
	// fmt.Println(sig.Content, ":", payload2)

	// fmt.Println(payload)

	cmd := exec.Command("curl", "-X", "POST", "--cert-type", "P12", "--cert", "PRiSM/PRiSMRESTClient_COMM.GEN.PKICTest.210910.1-2.pfx", "--cacert", "PRiSM/ArrisPKICenterRootandSubCA.cer", "-H", "Content-Type: application/json", "-d", payload, "https://usacasd-prism-test.arrisi.com:4443/api/v1/signatureoverhash")
        stdout, _ := cmd.StdoutPipe()
        scanner := bufio.NewScanner(stdout)
        done := make(chan bool)
	cmd_ret := ""
        go func() {
            for scanner.Scan() {
		cmd_ret = scanner.Text()
                // fmt.Printf(scanner.Text())
            }
            done <- true
        }()
        cmd.Start()
        <- done
        err = cmd.Wait()
	// fmt.Println("signature is:", cmd_ret)
        signRec.Signature = strings.Replace(cmd_ret, "\"", "", -1)

	//
	// Using resty client - not build, to work it out later
	//
	// Create a Resty Client
	// client := resty.New()
	// Custom Root certificates, just supply .pem file.
	// client.SetRootCertificate("/path/to/root/pemFile1.pem")
	// Adding Client Certificates, add one or more certificates
	// Parsing public/private key pair from a pair of files. The files must contain PEM encoded data.
	// cert1, err := tls.LoadX509KeyPair("certs/client.pem", "certs/client.key")
	// if err != nil {
		// log.Fatalf("ERROR client certificate: %s", err)
		// return nil, err
	// }
	// client.SetCertificates(cert1)
	// POST JSON string
	// No need to set content type, if you have client level setting
	// resp, err := client.R().
		// SetHeader("Content-Type", "application/json").
		// SetBody(`{"username":"testuser", "password":"testpass"}`).
		// SetResult(&AuthSuccess{}).    // or SetResult(AuthSuccess{}).
		// Post("https://myapp.com/login")

        // signing log
        addrs, err1 := net.InterfaceAddrs()
        if err1 != nil {
            panic(err1)
        }
        for _, addr := range addrs {
            ipNet, ok := addr.(*net.IPNet)
            if ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
        //        fmt.Println(ipNet.IP)
	        signRec.IpAddr = append(signRec.IpAddr, ipNet.IP.String())
            }
        }
        as, err2 := getMacAddr()
        if err2 != nil {
            log.Fatal(err2)
        }
        for _, a := range as {
        //     fmt.Println(a)
	    signRec.MacAddr = append(signRec.MacAddr, string(a))
        }
        currentTime := time.Now()
        // fmt.Println(currentTime.String())
        signRec.TimeStamp = currentTime.String()
        // fmt.Println("Notary signing key ID:", pk.ID())
	signRec.NotaryKeyId = pk.ID()

	// fmt.Println(signRec)

        signJson, err3 := json.Marshal(&signRec)
        if err3 != nil {
            log.Fatal(err3)
        }
	signString := string(signJson)
	signString = strings.Replace(signString, "\"{", "{", 1)
	signString = strings.Replace(signString, "}\"", "}", 1)
	signString = strings.Replace(signString, "\\\"", "\"", -1)
        fmt.Println("singRec is:", signString)
	filename := "/tmp/" + pk.ID() + ".log"
	fmt.Println("write to file: ", filename)
	err = os.WriteFile(filename, []byte(signString), 0644)
	check(err)

	return sig.Content, nil
}

// SignatureAlgorithm returns the signing algorithm based on the type of
// PublicKey algorithm.
func (pk *RemotePrivateKey) SignatureAlgorithm() data.SigAlgorithm {
	switch pk.PublicKey.Algorithm() {
	case data.ECDSAKey, data.ECDSAx509Key:
		return data.ECDSASignature
	case data.RSAKey, data.RSAx509Key:
		return data.RSAPSSSignature
	case data.ED25519Key:
		return data.EDDSASignature
	default: // unknown
		return ""
	}
}

// CryptoSigner returns a crypto.Signer tha wraps the RemotePrivateKey. Needed
// for implementing the interface.
func (pk *RemotePrivateKey) CryptoSigner() crypto.Signer {
	return &RemoteSigner{RemotePrivateKey: *pk}
}

// NotarySigner implements a RPC based Trust service that calls the Notary-signer Service
type NotarySigner struct {
	kmClient pb.KeyManagementClient
	sClient  pb.SignerClient

	healthClient healthpb.HealthClient
}

func healthCheck(d time.Duration, hc healthpb.HealthClient, serviceName string) (*healthpb.HealthCheckResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	req := &healthpb.HealthCheckRequest{
		Service: serviceName,
	}
	return hc.Check(ctx, req)
}

func healthCheckKeyManagement(d time.Duration, hc healthpb.HealthClient) error {
	out, err := healthCheck(d, hc, notary.HealthCheckKeyManagement)
	if err != nil {
		return err
	}
	if out.Status != healthpb.HealthCheckResponse_SERVING {
		return fmt.Errorf("got the serving status of %s: %s, want %s", "KeyManagement", out.Status, healthpb.HealthCheckResponse_SERVING)
	}
	return nil
}

func healthCheckSigner(d time.Duration, hc healthpb.HealthClient) error {
	out, err := healthCheck(d, hc, notary.HealthCheckSigner)
	if err != nil {
		return err
	}
	if out.Status != healthpb.HealthCheckResponse_SERVING {
		return fmt.Errorf("got the serving status of %s: %s, want %s", "Signer", out.Status, healthpb.HealthCheckResponse_SERVING)
	}
	return nil
}

// CheckHealth are used to probe whether the server is able to handle rpcs.
func (trust *NotarySigner) CheckHealth(d time.Duration, serviceName string) error {
	switch serviceName {
	case notary.HealthCheckKeyManagement:
		return healthCheckKeyManagement(d, trust.healthClient)
	case notary.HealthCheckSigner:
		return healthCheckSigner(d, trust.healthClient)
	case notary.HealthCheckOverall:
		if err := healthCheckKeyManagement(d, trust.healthClient); err != nil {
			return err
		}
		return healthCheckSigner(d, trust.healthClient)
	default:
		return fmt.Errorf("unknown grpc service %s", serviceName)
	}
}

// NewGRPCConnection is a convenience method that returns GRPC Client Connection given a hostname, endpoint, and TLS options
func NewGRPCConnection(hostname string, port string, tlsConfig *tls.Config) (*grpc.ClientConn, error) {
	var opts []grpc.DialOption
	netAddr := net.JoinHostPort(hostname, port)
	creds := credentials.NewTLS(tlsConfig)
	opts = append(opts, grpc.WithTransportCredentials(creds))
	return grpc.Dial(netAddr, opts...)
}

// NewNotarySigner is a convenience method that returns NotarySigner given a GRPC connection
func NewNotarySigner(conn *grpc.ClientConn) *NotarySigner {
	kmClient := pb.NewKeyManagementClient(conn)
	sClient := pb.NewSignerClient(conn)
	hc := healthpb.NewHealthClient(conn)

	return &NotarySigner{
		kmClient:     kmClient,
		sClient:      sClient,
		healthClient: hc,
	}
}

// Create creates a remote key and returns the PublicKey associated with the remote private key
func (trust *NotarySigner) Create(role data.RoleName, gun data.GUN, algorithm string) (data.PublicKey, error) {
	publicKey, err := trust.kmClient.CreateKey(context.Background(),
		&pb.CreateKeyRequest{Algorithm: algorithm, Role: role.String(), Gun: gun.String()})
	if err != nil {
		return nil, err
	}
	public := data.NewPublicKey(publicKey.KeyInfo.Algorithm.Algorithm, publicKey.PublicKey)
	return public, nil
}

// AddKey adds a key
func (trust *NotarySigner) AddKey(role data.RoleName, gun data.GUN, k data.PrivateKey) error {
	return errors.New("adding a key to NotarySigner is not supported")
}

// RemoveKey deletes a key by ID - if the key didn't exist, succeed anyway
func (trust *NotarySigner) RemoveKey(keyid string) error {
	_, err := trust.kmClient.DeleteKey(context.Background(), &pb.KeyID{ID: keyid})
	return err
}

// GetKey retrieves a key by ID - returns nil if the key doesn't exist
func (trust *NotarySigner) GetKey(keyid string) data.PublicKey {
	pubKey, _, err := trust.getKeyInfo(keyid)
	if err != nil {
		return nil
	}
	return pubKey
}

func (trust *NotarySigner) getKeyInfo(keyid string) (data.PublicKey, data.RoleName, error) {
	keyInfo, err := trust.kmClient.GetKeyInfo(context.Background(), &pb.KeyID{ID: keyid})
	if err != nil {
		return nil, "", err
	}
	return data.NewPublicKey(keyInfo.KeyInfo.Algorithm.Algorithm, keyInfo.PublicKey), data.RoleName(keyInfo.Role), nil
}

// GetPrivateKey retrieves by ID an object that can be used to sign, but that does
// not contain any private bytes.  If the key doesn't exist, returns an error.
func (trust *NotarySigner) GetPrivateKey(keyid string) (data.PrivateKey, data.RoleName, error) {
	pubKey, role, err := trust.getKeyInfo(keyid)
	if err != nil {
		return nil, "", err
	}
	return NewRemotePrivateKey(pubKey, trust.sClient), role, nil
}

// ListKeys not supported for NotarySigner
func (trust *NotarySigner) ListKeys(role data.RoleName) []string {
	return []string{}
}

// ListAllKeys not supported for NotarySigner
func (trust *NotarySigner) ListAllKeys() map[string]data.RoleName {
	return map[string]data.RoleName{}
}
