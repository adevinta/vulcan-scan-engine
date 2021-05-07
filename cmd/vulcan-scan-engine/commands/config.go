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
	Period       int `mapstructure:"period"` // seconds
}

type config struct {
	Log           logConfig
	Server        serverConfig
	DB            dbConfig
	Vulcan        checktypesInformer
	SQS           queue.Config
	EventsSNS     notify.Config `mapstructure:"events_sns"`
	Metrics       metricsConfig
	Stream        streamConfig
	ChecksCreator checkCreatorConfig `mapstructure:"check_creator"`
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
