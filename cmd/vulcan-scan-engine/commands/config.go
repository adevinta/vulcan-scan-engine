/*
Copyright 2021 Adevinta
*/

package commands

import (
	"fmt"
	"os"
	"os/user"

	"github.com/adevinta/vulcan-scan-engine/pkg/notify"
	"github.com/adevinta/vulcan-scan-engine/pkg/queue"
	"github.com/spf13/viper"
)

type serverConfig struct {
	Port string
}

type dbConfig struct {
	ConnString       string `mapstructure:"connection_string"`
	MigrationsSubBir string `mapstructure:"migrations_subdir"`
}

type checktypesInformer struct {
	Schema string
	Host   string
	Cache  int
}

type logConfig struct {
	Level string
}

type metricsConfig struct {
	Enabled bool
}

type streamConfig struct {
	URL string
}

type checkCreatorConfig struct {
	NumOfWorkers int `mapstructure:"num_of_workers"`
	Period       int `mapstructure:"period"`     // seconds
	Checkpoint   int `mapstructure:"checkpoint"` // update scan every checks
}

type checktypeQueues struct {
	ARN        string
	Checktypes []string
}

type checktypeQueueConfig map[string]checktypeQueues

// ARNs returns map with the following shape: ["queuename":"arn1"]
func (c checktypeQueueConfig) ARNs() map[string]string {
	var qarns = make(map[string]string)
	for qType, q := range c {
		if q.ARN != "" {
			qarns[qType] = q.ARN
		}
	}
	return qarns
}

// Names returns a map with the following shape:
// ["default":"default","vulcan-nessus":"nessus"]
func (c checktypeQueueConfig) Names() map[string]string {
	var ctQNames = make(map[string]string)
	for qType, q := range c {
		if qType == "default" {
			ctQNames["default"] = "default"
			continue
		}
		cts := q.Checktypes
		if len(cts) < 1 {
			continue
		}
		for _, ct := range cts {
			ctQNames[ct] = qType
		}
	}
	return ctQNames
}

type config struct {
	Log           logConfig
	Server        serverConfig
	DB            dbConfig
	Vulcan        checktypesInformer
	SQS           queue.Config
	ScansSNS      notify.Config `mapstructure:"scans_sns"`
	ChecksSNS     notify.Config `mapstructure:"checks_sns"`
	Metrics       metricsConfig
	Stream        streamConfig
	ChecksCreator checkCreatorConfig   `mapstructure:"check_creator"`
	CTQueues      checktypeQueueConfig `mapstructure:"queues"`
}

func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		usr, err := user.Current()
		if err != nil {
			fmt.Println("Can't get current user:", err)
			os.Exit(1)
		}

		// Search config in home directory with name ".vulcan-scan-engine" (without extension).
		viper.AddConfigPath(usr.HomeDir)
		viper.SetConfigName(".vulcan-scan-engine")
	}

	if err := viper.ReadInConfig(); err != nil {
		fmt.Println("Can't read config:", err)
		os.Exit(1)
	}

	if err := viper.Unmarshal(&cfg); err != nil {
		fmt.Println("Can't decode config:", err)
		os.Exit(1)
	}
}
