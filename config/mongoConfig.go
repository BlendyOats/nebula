package config

import (
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"time"
)

// ClientOpts mongoClient 连接客户端参数
var ClientOpts = options.Client().
	SetAuth(options.Credential{
		Username:      "admin",
		Password:      "123456",
	}).
	SetConnectTimeout(10 * time.Second).
	SetHosts([]string{"localhost:27017"}).
	SetMaxPoolSize(20).
	SetMinPoolSize(5).
	SetReadPreference(readpref.Primary())