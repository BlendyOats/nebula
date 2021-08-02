package yaml

import (
	"context"
	"fmt"
	"github.com/slackhq/nebula/config"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
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
	AmLighthouse string     `yaml:"am_lighthouse"`
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

func ReadToYaml(hostName string) Nebula {

	var result Nebula

	connect, err := mongo.Connect(context.TODO(), config.ClientOpts)
	if err != nil {
		fmt.Errorf("数据库连接失败:", err)
	}
	collection := connect.Database("nebula_db").Collection("nebula_config")
	one := collection.FindOne(context.TODO(), bson.M{"name": hostName})
	if err = one.Decode(&result); err == nil {
		fmt.Printf("result: %+v\n", result)
		return result
	}
	return Nebula{}
}



func WriteToYaml(nebula Nebula) {

	connect, err := mongo.Connect(context.TODO(), config.ClientOpts)
	if err != nil {
		fmt.Errorf("数据库连接失败:", err)
	}
	collection := connect.Database("nebula_db").Collection("nebula_config")
	m := make(map[string][]string)
	m["192.168.100.1"] = []string{"8.212.29.4:4242"}
	_, err = collection.InsertOne(context.TODO(), nebula)
	checkError(err)
	// 输出到本地文件
	/*	fmt.Print(stu.StaticHostMap)
		data, err := yaml.Marshal(stu)
		checkError(err)
		err = ioutil.WriteFile(src, data, 0777)
		checkError(err)*/

}


/*func main() {

	m := make(map[string][]string)
	m["192.168.100.1"] = []string{"8.212.29.4:4242"}

	//src := "/Users/oats/Documents/nebula/one/a.yaml"
	writeToYaml(Nebula{
		Group: "seeed",
		Name: "host01",
		Pki:           Pki{"/Users/oats/Documents/nebula/one/ca.crt", "/Users/oats/Documents/nebula/one/test01.crt", "/Users/oats/Documents/nebula/one/test01.crt"},
		StaticHostMap: m,
		Lighthouse: Lighthouse{
			AmLighthouse: false,
			Interval:     0,
			Hosts:        []string{"192.168.100.1"},
		},
		Listen:  Listen{"0.0.0.0", 0},
		Punchy:  Punchy{true},
		Tun:     Tun{false, "nebula01", false, false, 500, 1300},
		Logging: Logging{"debug", "text"},

		Firewall: Firewall{
			Conntrack: Conntrack{"12m", "3m", "10m", 100000},
			Outbound:  []Bound{{"any", "any", "any"}},
			Inbound:   []Bound{{"any", "any", "any"}},
		},
	})
	//readFromXml(src)
}*/

/*func main() {
	toYaml := readToYaml("lighthouse01")
	fmt.Print(toYaml)
	data, err := yaml.Marshal(toYaml)
	checkError(err)
	err = ioutil.WriteFile("/Users/oats/Documents/nebula/one/test.yaml", data, 0777)
	checkError(err)
}*/
