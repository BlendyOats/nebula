// +build !windows

package main

import (
	logredis "github.com/rogierlommers/logrus-redis-hook"
	_ "github.com/rogierlommers/logrus-redis-hook"
	"github.com/sirupsen/logrus"
)



func HookLogger(l *logrus.Logger) {
	config := logredis.HookConfig{
		Host:     "127.0.0.1",
		Key:      "server_logger",
		Format:   "v1",
		App:      "my_app_name",
		Port:     6479,
		Hostname: "my_app_hostname",
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
