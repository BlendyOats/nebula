package main

import (
	"flag"
	"fmt"
	logredis "github.com/rogierlommers/logrus-redis-hook"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula"
	yaml2 "github.com/slackhq/nebula/yaml"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"path"
	"strings"
)

// A version string that can be set with
//
//     -ldflags "-X main.Build=SOMEVERSION"
//
// at compile-time.
var Build string

func main() {
	configPath := flag.String("config", "", "Path to either a file or directory to load configuration from")
	light := flag.String("light", "", "是否为lightHouse")
	configTest := flag.Bool("test", false, "Test the config and print the end result. Non zero exit indicates a faulty config")
	printVersion := flag.Bool("version", false, "Print version")
	printUsage := flag.Bool("help", false, "Print command line usage")
	flag.Parse()
	l := logrus.New()
	HookLogger(l)
	l.Out = os.Stdout
	config := nebula.NewConfig(l)
	// 截取配置文件名
	var hostPath string
	hostPath = path.Base(config.FindPath(*configPath))
	var host01 string
	host01 = path.Ext(hostPath)
	var configName string
	configName = strings.TrimSuffix(hostPath, host01)
	// 如果为server则从数据库获取yaml详细信息后生成配置，客户端则为从远程接口获取
	if *light == "" {

	} else {
		toYaml := yaml2.ReadToYaml(configName)
		fmt.Print(toYaml)
		data, _ := yaml.Marshal(toYaml)
		_ = ioutil.WriteFile("./"+configName+".yaml", data, 0777)
	}

	if *printVersion {
		fmt.Printf("Version: %s\n", Build)
		os.Exit(0)
	}

	if *printUsage {
		flag.Usage()
		os.Exit(0)
	}

	if *configPath == "" {
		fmt.Println("-config flag must be set")
		flag.Usage()
		os.Exit(1)
	}
	err := config.Load(*configPath)
	if err != nil {
		fmt.Printf("failed to load config: %s", err)
		os.Exit(1)
	}

	// 进入主程序
	// *configTest 是否为测试
	fmt.Print("准备进入主程序。。。。。")
	c, err := nebula.Main(config, *configTest, Build, l, nil)

	switch v := err.(type) {
	case nebula.ContextualError:
		v.Log(l)
		os.Exit(1)
	case error:
		l.WithError(err).Error("Failed to start")
		os.Exit(1)
	}

	if !*configTest {
		c.Start()
		c.ShutdownBlock()
	}
	os.Exit(0)
}

func HookLogger(l *logrus.Logger) {
	config := logredis.HookConfig{
		Host:     "127.0.0.1",
		Key:      "client_nebula",
		Format:   "v1",
		App:      "client_nebula",
		Port:     6479,
		Hostname: "client_nebula",
		DB:       0, // optional
		TTL:      3600,
	}
	hook, err := logredis.NewHook(config)
	if err == nil {
		l.AddHook(hook)
	} else {
		l.Errorf("logredis error: %q", err)
	}

}
