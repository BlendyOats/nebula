package nebula

import (
	"context"
	"errors"
	"fmt"
	"github.com/slackhq/nebula/config"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"io/ioutil"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
)

type CertState struct {
	certificate         *cert.NebulaCertificate
	rawCertificate      []byte
	rawCertificateNoKey []byte
	publicKey           []byte
	privateKey          []byte
}

type caModel struct {
	Name       *string   `json:"name"`
	Type       *string   `json:"type"`
	Ca         *string   `json:"ca"`
	LightHouse *string   `json:"lightHouse"`
	Created    time.Time `json:"created"`
	Updated    time.Time `json:"updated"`
	Deleted    time.Time `json:"deleted"`
}

func NewCertState(certificate *cert.NebulaCertificate, privateKey []byte) (*CertState, error) {
	// Marshal the certificate to ensure it is valid
	rawCertificate, err := certificate.Marshal()
	if err != nil {
		return nil, fmt.Errorf("invalid nebula certificate on interface: %s", err)
	}

	publicKey := certificate.Details.PublicKey
	cs := &CertState{
		rawCertificate: rawCertificate,
		certificate:    certificate, // PublicKey has been set to nil above
		privateKey:     privateKey,
		publicKey:      publicKey,
	}

	cs.certificate.Details.PublicKey = nil
	rawCertNoKey, err := cs.certificate.Marshal()
	if err != nil {
		return nil, fmt.Errorf("error marshalling certificate no key: %s", err)
	}
	cs.rawCertificateNoKey = rawCertNoKey
	// put public key back
	cs.certificate.Details.PublicKey = cs.publicKey
	return cs, nil
}

func NewCertStateFromConfig(c *Config) (*CertState, error) {
	var result caModel
	var err error
	var pemPrivateKey []byte
	var rawCert []byte
	// 获取hostName
	hostName := c.GetString("name", "")
	// 引入数据库
	connect, err := mongo.Connect(context.TODO(), config.ClientOpts)
	if err == nil {
		collection := connect.Database("nebula_db").Collection("nebula_ca")
		rawCAKey := collection.FindOne(context.TODO(), bson.M{"name": hostName, "type": "key"})
		if rawCAKey.Decode(&result); err == nil {
			pemPrivateKey = []byte(*result.Ca)
		}
		rawCACert := collection.FindOne(context.TODO(), bson.M{"name": hostName, "type": "cert"})
		if rawCACert.Decode(&result); err == nil {
			rawCert = []byte(*result.Ca)
		}
	} else {
		privPathOrPEM := c.GetString("pki.key", "")
		if privPathOrPEM == "" {
			// Support backwards compat with the old x509
			//TODO: remove after this is rolled out everywhere - NB 2018/02/23
			privPathOrPEM = c.GetString("x509.key", "")
		}

		if privPathOrPEM == "" {
			return nil, errors.New("no pki.key path or PEM data provided")
		}

		if strings.Contains(privPathOrPEM, "-----BEGIN") {
			pemPrivateKey = []byte(privPathOrPEM)
			privPathOrPEM = "<inline>"
		} else {
			pemPrivateKey, err = ioutil.ReadFile(privPathOrPEM)
			if err != nil {
				return nil, fmt.Errorf("unable to read pki.key file %s: %s", privPathOrPEM, err)
			}
		}

		pubPathOrPEM := c.GetString("pki.cert", "")
		if pubPathOrPEM == "" {
			// Support backwards compat with the old x509
			//TODO: remove after this is rolled out everywhere - NB 2018/02/23
			pubPathOrPEM = c.GetString("x509.cert", "")
		}

		if pubPathOrPEM == "" {
			return nil, errors.New("no pki.cert path or PEM data provided")
		}

		if strings.Contains(pubPathOrPEM, "-----BEGIN") {
			rawCert = []byte(pubPathOrPEM)
			pubPathOrPEM = "<inline>"
		} else {
			rawCert, err = ioutil.ReadFile(pubPathOrPEM)
			if err != nil {
				return nil, fmt.Errorf("unable to read pki.cert file %s: %s", pubPathOrPEM, err)
			}
		}
	}
	rawKey, _, err := cert.UnmarshalX25519PrivateKey(pemPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("error while unmarshaling pki.key %s: %s", pemPrivateKey, err)
	}
	nebulaCert, _, err := cert.UnmarshalNebulaCertificateFromPEM(rawCert)
	if err != nil {
		return nil, fmt.Errorf("error while unmarshaling pki.cert %s: %s", rawCert, err)
	}

	if nebulaCert.Expired(time.Now()) {
		return nil, fmt.Errorf("nebula certificate for this host is expired")
	}

	if len(nebulaCert.Details.Ips) == 0 {
		return nil, fmt.Errorf("no IPs encoded in certificate")
	}

	if err = nebulaCert.VerifyPrivateKey(rawKey); err != nil {
		return nil, fmt.Errorf("private key is not a pair with public key in nebula cert")
	}

	return NewCertState(nebulaCert, rawKey)
}

func loadCAFromConfig(l *logrus.Logger, c *Config) (*cert.NebulaCAPool, error) {
	var result caModel
	var err error
	var rawCA []byte
	hostGroup := c.GetString("group", "")
	logrus.Warn("这是一个测试hostname：", hostGroup)
	connect, _ := mongo.Connect(context.TODO(), config.ClientOpts)
	collection := connect.Database("nebula_db").Collection("nebula_ca")
	rawCAKey := collection.FindOne(context.TODO(), bson.M{"name": hostGroup,"type": "cert"})

	if rawCAKey.Decode(&result); err == nil {
		rawCAKey.Decode(&result)
		rawCA = []byte(*result.Ca)
	} else {
		caPathOrPEM := c.GetString("pki.ca", "")
		if caPathOrPEM == "" {
			// Support backwards compat with the old x509
			//TODO: remove after this is rolled out everywhere - NB 2018/02/23
			caPathOrPEM = c.GetString("x509.ca", "")
		}
		if caPathOrPEM == "" {
			return nil, errors.New("no pki.ca path or PEM data provided")
		}

		if strings.Contains(caPathOrPEM, "-----BEGIN") {
			rawCA = []byte(caPathOrPEM)
			caPathOrPEM = "<inline>"
		} else {
			rawCA, err = ioutil.ReadFile(caPathOrPEM)
			if err != nil {
				return nil, fmt.Errorf("unable to read pki.ca file %s: %s", caPathOrPEM, err)
			}
		}
	}

	CAs, err := cert.NewCAPoolFromBytes(rawCA)
	if err != nil {
		return nil, fmt.Errorf("error while adding CA certificate to CA trust store: %s", err)
	}

	for _, fp := range c.GetStringSlice("pki.blocklist", []string{}) {
		l.WithField("fingerprint", fp).Infof("Blocklisting cert")
		CAs.BlocklistFingerprint(fp)
	}

	// Support deprecated config for at leaast one minor release to allow for migrations
	for _, fp := range c.GetStringSlice("pki.blacklist", []string{}) {
		l.WithField("fingerprint", fp).Infof("Blocklisting cert")
		l.Warn("pki.blacklist is deprecated and will not be supported in a future release. Please migrate your config to use pki.blocklist")
		CAs.BlocklistFingerprint(fp)
	}

	return CAs, nil
}
