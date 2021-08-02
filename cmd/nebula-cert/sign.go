package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"github.com/skip2/go-qrcode"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	yaml2 "github.com/slackhq/nebula/yaml"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/curve25519"
	"io"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"time"
)

func checkError(err error) {
	if err != nil {
		panic(err)
	}
}

type Pki struct {
	Ca   string `yaml:"ca"`
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

type Lighthouse struct {
	AmLighthouse string   `yaml:"am_lighthouse"`
	Interval     int      `yaml:"interval"`
	Hosts        []string `yaml:"hosts"`
}
type Listen struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}
type Punchy struct {
	Punch bool `yaml:"punch"`
}
type Tun struct {
	Disabled           bool   `yaml:"disabled"`
	Dev                string `yaml:"dev"`
	DropLocalBroadcast bool   `yaml:"drop_local_broadcast"`
	DropMulticast      bool   `yaml:"drop_multicast"`
	TxQueue            int    `yaml:"tx_queue"`
	Mtu                int    `yaml:"mtu"`
}
type Logging struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

type Firewall struct {
	Conntrack Conntrack `yaml:"conntrack"`
	Outbound  []Bound   `yaml:"outbound"`
	Inbound   []Bound   `yaml:"inbound"`
}

type Conntrack struct {
	TcpTimeout     string `yaml:"tcp_timeout"`
	UdpTimeout     string `yaml:"udp_timeout"`
	DefaultTimeout string `yaml:"default_timeout"`
	MaxConnections int    `yaml:"max_connections"`
}

type Bound struct {
	Port  string `yaml:"port"`
	Proto string `yaml:"proto"`
	Host  string `yaml:"host"`
}

type Nebula struct {
	Group         string              `yaml:"group"`
	Name          string              `yaml:"name"`
	Pki           Pki                 `yaml:"pki"`
	StaticHostMap map[string][]string `yaml:"static_host_map"`
	Lighthouse    Lighthouse          `yaml:"lighthouse"`
	Listen        Listen              `yaml:"listen"`
	Punchy        Punchy              `yaml:"punchy"`
	Tun           Tun                 `yaml:"tun"`
	Logging       Logging             `yaml:"logging"`
	Firewall      Firewall            `yaml:"firewall"`
}
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
	light       *string
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
	sf.light = sf.set.String("light", "", "是否是lighthouse")
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
	collectionInfo := connect.Database("nebula_db").Collection("nebula_info")
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
		bson.M{"name": sf.name, "type": "key", "ca": cert.MarshalX25519PrivateKey(rawPriv), "lightHouse": sf.parent, "created": now, "updated": now, "deleted": now},
		bson.M{"name": sf.name, "type": "cert", "ca": b, "lightHouse": sf.parent, "created": now, "updated": now, "deleted": now},
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
	// 插入详情信息
	collectionInfo.InsertOne(todo, bson.M{"name": sf.name, "ips": ip, "lightHouse": sf.parent, "status": "unLine", "created": now, "updated": now, "deleted": now})
	// 输出二维码
	if *sf.outQRPath != "" {
		b, err = qrcode.Encode(string(b), qrcode.Medium, -5)
		if err != nil {
			return fmt.Errorf("error while generating qr code: %s", err)
		}

		//err = ioutil.WriteFile(*sf.outQRPath, b, 0600)
		if err != nil {
			return fmt.Errorf("error while writing out-qr: %s", err)
		}
	}
	s := ip.String()
	strings.Split(s, "")
	m := make(map[string][]string)
	m["192.168.100.1"] = []string{"8.212.29.4:4242"}
	// 生成配置
	yaml2.WriteToYaml(yaml2.Nebula{
		Group: *sf.parent,
		Name:  *sf.name,
		Pki: yaml2.Pki{
			Ca:   "./ca.crt",
			Cert: "./" + *sf.name + ".crt",
			Key:  "./" + *sf.name + ".key",
		},
		StaticHostMap: m,
		Lighthouse: yaml2.Lighthouse{
			AmLighthouse: *sf.light,
			Interval:     60,
			Hosts:        []string{"192.168.100.1"},
		},
		Listen: yaml2.Listen{
			Host: "0.0.0.0",
			Port: 0,
		},
		Punchy: yaml2.Punchy{Punch: true},
		Tun: yaml2.Tun{
			Disabled:           false,
			Dev:                *sf.parent,
			DropLocalBroadcast: false,
			DropMulticast:      false,
			TxQueue:            500,
			Mtu:                1300,
		},
		Logging: yaml2.Logging{
			Level:  "debug",
			Format: "text",
		},
		Firewall: yaml2.Firewall{
			Conntrack: yaml2.Conntrack{
				TcpTimeout:     "12m",
				UdpTimeout:     "3m",
				DefaultTimeout: "10m",
				MaxConnections: 100000,
			},
			Outbound: []yaml2.Bound{{"any", "any", "any"}},
			Inbound:  []yaml2.Bound{{"any", "any", "any"}},
		},
	})

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
