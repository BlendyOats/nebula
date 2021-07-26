package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"github.com/slackhq/nebula/config"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"io"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"
	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"
)

type signFlags struct {
	set         *flag.FlagSet
	caKeyPath   *string
	caCertPath  *string
	name        *string
	ip          *string
	duration    *time.Duration
	inPubPath   *string
	outKeyPath  *string
	outCertPath *string
	outQRPath   *string
	groups      *string
	subnets     *string
	parent      *string
}

type caModel struct {
	Name    *string   `json:"name"`
	Type    *string   `json:"type"`
	Ca      *string   `json:"ca"`
	Created time.Time `json:"created"`
	Updated time.Time `json:"updated"`
	Deleted time.Time `json:"deleted"`
}

func newSignFlags() *signFlags {
	sf := signFlags{set: flag.NewFlagSet("sign", flag.ContinueOnError)}
	sf.set.Usage = func() {}
	sf.caKeyPath = sf.set.String("ca-key", "ca.key", "Optional: path to the signing CA key")
	sf.caCertPath = sf.set.String("ca-crt", "ca.crt", "Optional: path to the signing CA cert")
	sf.name = sf.set.String("name", "", "Required: name of the cert, usually a hostname")
	sf.parent = sf.set.String("parent", "", "获取root ca")
	sf.ip = sf.set.String("ip", "", "Required: ip and network in CIDR notation to assign the cert")
	sf.duration = sf.set.Duration("duration", 0, "Optional: how long the cert should be valid for. The default is 1 second before the signing cert expires. Valid time units are seconds: \"s\", minutes: \"m\", hours: \"h\"")
	sf.inPubPath = sf.set.String("in-pub", "", "Optional (if out-key not set): path to read a previously generated public key")
	sf.outKeyPath = sf.set.String("out-key", "", "Optional (if in-pub not set): path to write the private key to")
	sf.outCertPath = sf.set.String("out-crt", "", "Optional: path to write the certificate to")
	sf.outQRPath = sf.set.String("out-qr", "", "Optional: output a qr code image (png) of the certificate")
	sf.groups = sf.set.String("groups", "", "Optional: comma separated list of groups")
	sf.subnets = sf.set.String("subnets", "", "Optional: comma separated list of subnet this cert can serve for")
	return &sf

}

func signCert(args []string, out io.Writer, errOut io.Writer) error {
	// 公钥
	var result caModel
	now := time.Now()
	todo := context.TODO()
	sf := newSignFlags()
	err := sf.set.Parse(args)
	if err != nil {
		return err
	}
	// 引入数据库
	connect, err := mongo.Connect(context.TODO(), config.ClientOpts)
	if err != nil {
		return err
	}
	collection := connect.Database("nebula_db").Collection("nebula_ca")
	if err := mustFlagString("ca-key", sf.caKeyPath); err != nil {
		return err
	}
	if err := mustFlagString("ca-crt", sf.caCertPath); err != nil {
		return err
	}
	if err := mustFlagString("name", sf.name); err != nil {
		return err
	}
	if err := mustFlagString("ip", sf.ip); err != nil {
		return err
	}
	if err := mustFlagString("parent", sf.parent); err != nil {
		return fmt.Errorf("这是一个错误: %s", err)
	}
	if *sf.inPubPath != "" && *sf.outKeyPath != "" {
		return newHelpErrorf("cannot set both -in-pub and -out-key")
	}
	// 从db查找
	rawCAKey := collection.FindOne(context.TODO(), bson.M{"name": *sf.parent, "type": "key"})
	if err = rawCAKey.Decode(&result); err != nil {
		return fmt.Errorf("解析结果失败: %s", err)
	}
	// 获取ca
	priCa := *result.Ca
	//rawCAKey, err := ioutil.ReadFile(*sf.caKeyPath)
	//if err != nil {
	//	return fmt.Errorf("error while reading ca-key: %s", err)
	//}
	caKey, _, err := cert.UnmarshalEd25519PrivateKey([]byte(priCa))
	if err != nil {
		return fmt.Errorf("解析ca key失败: %s", err)
	}
	//rawCACert, err := ioutil.ReadFile(*sf.caCertPath)
	rawCACert := collection.FindOne(context.TODO(), bson.M{"name": *sf.parent, "type": "cert"})
	if err = rawCACert.Decode(&result); err == nil {
		fmt.Printf("result: %+v\n", result)
	}
	// 获取ca
	prawCa := *result.Ca
	if err != nil {
		return fmt.Errorf("读取ca cert失败 %s", err)
	}

	// 解密
	caCert, _, err := cert.UnmarshalNebulaCertificateFromPEM([]byte(prawCa))
	if err != nil {
		return fmt.Errorf("error while parsing ca-crt: %s", err)
	}

	issuer, err := caCert.Sha256Sum()
	if err != nil {
		return fmt.Errorf("error while getting -ca-crt fingerprint: %s", err)
	}

	if caCert.Expired(time.Now()) {
		return fmt.Errorf("ca certificate is expired")
	}

	// if no duration is given, expire one second before the root expires
	if *sf.duration <= 0 {
		*sf.duration = time.Until(caCert.Details.NotAfter) - time.Second*1
	}

	// 解析
	ip, ipNet, err := net.ParseCIDR(*sf.ip)
	if err != nil {
		return newHelpErrorf("invalid ip definition: %s", err)
	}
	ipNet.IP = ip

	groups := []string{}
	if *sf.groups != "" {
		for _, rg := range strings.Split(*sf.groups, ",") {
			g := strings.TrimSpace(rg)
			if g != "" {
				groups = append(groups, g)
			}
		}
	}

	// 子网
	subnets := []*net.IPNet{}
	if *sf.subnets != "" {
		for _, rs := range strings.Split(*sf.subnets, ",") {
			rs := strings.Trim(rs, " ")
			if rs != "" {
				_, s, err := net.ParseCIDR(rs)
				if err != nil {
					return newHelpErrorf("invalid subnet definition: %s", err)
				}
				subnets = append(subnets, s)
			}
		}
	}

	var pub, rawPriv []byte
	if *sf.inPubPath != "" {
		rawPub, err := ioutil.ReadFile(*sf.inPubPath)
		if err != nil {
			return fmt.Errorf("error while reading in-pub: %s", err)
		}
		pub, _, err = cert.UnmarshalX25519PublicKey(rawPub)
		if err != nil {
			return fmt.Errorf("error while parsing in-pub: %s", err)
		}
	} else {
		pub, rawPriv = x25519Keypair()
	}

	nc := cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:      *sf.name,
			Ips:       []*net.IPNet{ipNet},
			Groups:    groups,
			Subnets:   subnets,
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(*sf.duration),
			PublicKey: pub,
			IsCA:      false,
			Issuer:    issuer,
		},
	}

	if err := nc.CheckRootConstrains(caCert); err != nil {
		return fmt.Errorf("refusing to sign, root certificate constraints violated: %s", err)
	}

	if *sf.outKeyPath == "" {
		*sf.outKeyPath = *sf.name + ".key"
	}

	if *sf.outCertPath == "" {
		*sf.outCertPath = *sf.name + ".crt"
	}

	if _, err := os.Stat(*sf.outCertPath); err == nil {
		return fmt.Errorf("refusing to overwrite existing cert: %s", *sf.outCertPath)
	}

	err = nc.Sign(caKey)
	if err != nil {
		return fmt.Errorf("error while signing: %s", err)
	}

	if *sf.inPubPath == "" {
		if _, err := os.Stat(*sf.outKeyPath); err == nil {
			return fmt.Errorf("refusing to overwrite existing key: %s", *sf.outKeyPath)
		}

		//err = ioutil.WriteFile(*sf.outKeyPath, cert.MarshalX25519PrivateKey(rawPriv), 0600)
		if err != nil {
			return fmt.Errorf("error while writing out-key: %s", err)
		}
	}

	b, err := nc.MarshalToPEM()
	if err != nil {
		return fmt.Errorf("error while marshalling certificate: %s", err)
	}

	// err = ioutil.WriteFile(*sf.outCertPath, b, 0600)
	docs := []interface{}{
		bson.M{"name": sf.name, "type": "key", "ca": cert.MarshalX25519PrivateKey(rawPriv),"parent":sf.parent, "created": now, "updated": now, "deleted": now},
		bson.M{"name": sf.name, "type": "cert", "ca": b,"parent":sf.parent, "created": now, "updated": now, "deleted": now},
	}
	if err != nil {
		return fmt.Errorf("error while writing out-crt: %s", err)
	}
	insertManyOpts := options.InsertMany().SetOrdered(false)
	insertManyResult, err := collection.InsertMany(todo, docs, insertManyOpts)
	if err != nil {
		return fmt.Errorf("error while install db: %s", err)
	}
	fmt.Println("ids:", insertManyResult.InsertedIDs)

	// 输出二维码
	if *sf.outQRPath != "" {
		b, err = qrcode.Encode(string(b), qrcode.Medium, -5)
		if err != nil {
			return fmt.Errorf("error while generating qr code: %s", err)
		}

		err = ioutil.WriteFile(*sf.outQRPath, b, 0600)
		if err != nil {
			return fmt.Errorf("error while writing out-qr: %s", err)
		}
	}

	return nil
}

func x25519Keypair() ([]byte, []byte) {
	var pubkey, privkey [32]byte
	if _, err := io.ReadFull(rand.Reader, privkey[:]); err != nil {
		panic(err)
	}
	curve25519.ScalarBaseMult(&pubkey, &privkey)
	return pubkey[:], privkey[:]
}

func signSummary() string {
	return "sign <flags>: create and sign a certificate"
}

func signHelp(out io.Writer) {
	sf := newSignFlags()
	out.Write([]byte("Usage of " + os.Args[0] + " " + signSummary() + "\n"))
	sf.set.SetOutput(out)
	sf.set.PrintDefaults()
}
