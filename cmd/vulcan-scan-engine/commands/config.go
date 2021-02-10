/*
Copyright 2021 Adevinta
*/

package commands

import (
	"fmt"
	"os"
	"os/user"

	"github.com/adevinta/vulcan-scan-engine/pkg/queue"
	"github.com/spf13/viper"
	"github.mpi-internal.com/spt-security/vulcan-scan-engine/pkg/notify"
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
}

type logConfig struct {
	Level string
}

type metricsConfig struct {
	Enabled bool
}

type checkCreatorConfig struct {
	NumOfWorkers int `mapstructure:"num_of_workers"`
	Period       int `mapstructure:"period"` // seconds
}

type checktypesQueuesConfig struct {
	SendToAgents bool                   `yaml:"sendToAgents"`
	Queues       []checktypeQueueConfig `yaml:"queues"` // ARNs of agent queues
}

// ARNs returns map with the following shape: ["queuename":"arn1"]
func (c checktypesQueuesConfig) ARNs() map[string]string {
	var qarns = make(map[string]string)
	for _, q := range c.Queues {
		qarns[q.Name] = q.ARN
	}
	return qarns
}

// Names returns a map with the following shape:
// ["default":"default","vulcan-nessus":"nessus"]
func (c checktypesQueuesConfig) Names() map[string]string {
	var ctQNames = make(map[string]string)
	for _, q := range c.Queues {
		if q.Name == "default" {
			ctQNames["default"] = "default"
			continue
		}
		cts := q.Checktypes
		if len(cts) < 1 {
			continue
		}
		for _, ct := range cts {
			ctQNames[ct] = q.Name
		}
	}
	return ctQNames
}

type checktypeQueueConfig struct {
	Name       string
	ARN        string
	Checktypes []string
}

type config struct {
	Log           logConfig
	Server        serverConfig
	DB            dbConfig
	Vulcan        checktypesInformer
	SQS           queue.Config
	ScansSNS      notify.Config
	ChecksSNS     notify.Config
	ChecksCreator checkCreatorConfig `mapstructure:"check_creator"`
	Metrics       metricsConfig
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
