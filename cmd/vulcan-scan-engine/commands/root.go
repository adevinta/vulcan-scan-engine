/*
Copyright 2021 Adevinta
*/

package commands

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path"
	"sync"
	"syscall"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	goaclient "github.com/goadesign/goa/client"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/adevinta/vulcan-core-cli/vulcan-core/client"
	metrics "github.com/adevinta/vulcan-metrics-client"

	"github.com/adevinta/vulcan-scan-engine/pkg/api/endpoint"
	"github.com/adevinta/vulcan-scan-engine/pkg/api/endpoint/middleware"
	"github.com/adevinta/vulcan-scan-engine/pkg/api/persistence"
	"github.com/adevinta/vulcan-scan-engine/pkg/api/persistence/db"
	"github.com/adevinta/vulcan-scan-engine/pkg/api/persistence/migrations"
	"github.com/adevinta/vulcan-scan-engine/pkg/api/service"
	"github.com/adevinta/vulcan-scan-engine/pkg/api/transport"
	checkmetrics "github.com/adevinta/vulcan-scan-engine/pkg/metrics"
	"github.com/adevinta/vulcan-scan-engine/pkg/notify"
	"github.com/adevinta/vulcan-scan-engine/pkg/queue"
	"github.com/adevinta/vulcan-scan-engine/pkg/scans"
	"github.com/adevinta/vulcan-scan-engine/pkg/scheduler"
)

var (
	cfgFile  string
	httpPort int
	cfg      config
	// all, debug, error, info, warn
	logLevels = map[string]func(log.Logger) log.Logger{
		"all": func(l log.Logger) log.Logger {
			return level.NewFilter(l, level.AllowAll())
		},
		"debug": func(l log.Logger) log.Logger {
			return level.NewFilter(l, level.AllowDebug())
		},
		"error": func(l log.Logger) log.Logger {
			return level.NewFilter(l, level.AllowError())
		},
		"info": func(l log.Logger) log.Logger {
			return level.NewFilter(l, level.AllowInfo())
		},
		"warn": func(l log.Logger) log.Logger {
			return level.NewFilter(l, level.AllowWarn())
		},
	}
)

type checkUpdateProcessor func(context.Context, []byte) error

func (p checkUpdateProcessor) Process(ctx context.Context, msg []byte) error {
	return p(ctx, msg)
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "vulcan-scan-engine",
	Short: "A command to spawn the vulcan-scan-engine and its associated exposed http api",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return startServer()
	},
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.Flags().StringVarP(&cfgFile, "config", "c", "", "config file (default is $HOME/.vulcan-scan-engine)")
	rootCmd.Flags().IntVarP(&httpPort, "port", "p", 0, "web server listening port")
	err := viper.BindPFlag("server.port", rootCmd.Flags().Lookup("port"))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func startServer() error {

	httpAddr := fmt.Sprintf(":%v", cfg.Server.Port)

	var logger log.Logger
	{
		logger = log.NewLogfmtLogger(log.NewSyncWriter(os.Stdout))
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
		logger = log.With(logger, "caller", log.DefaultCaller)

	}

	logger, err := logWithConfig(cfg.Log, logger)
	if err != nil {
		return err
	}

	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	if cfg.DB.MigrationsSubBir != "" {
		dir := path.Join(wd, cfg.DB.MigrationsSubBir)
		err = migrations.Ensure(cfg.DB.ConnString, dir)
		if err != nil {
			fmt.Printf("Error ensuring migrations for the database. %s", err)
			return err
		}
	}

	db, err := db.NewDB("postgres", cfg.DB.ConnString)
	if err != nil {
		fmt.Printf("Error opening DB connection: %v", err)
		return err
	}
	st := persistence.NewPersistence(db)

	apiClient := newVulcanCoreAPIClient(cfg.Vulcan)

	metricsClient, err := metrics.NewClient()
	if err != nil {
		return err
	}

	checkMetrics := &checkmetrics.Checks{Client: metricsClient}

	scansNotifier, err := notify.NewSNSNotifier(cfg.ScansSNS, logger)
	if err != nil {
		return err
	}
	checksNotifier, err := notify.NewSNSNotifier(cfg.ChecksSNS, logger)
	if err != nil {
		return err
	}

	var (
		creator interface {
			CreateScanChecks(id string) error
			CreateIncompleteScansChecks() error
		}
		sch *scheduler.Scheduler
	)

	producer, err := queue.NewMultiSQSProducer(cfg.CTQueues.ARNs(), logger)
	if err != nil {
		return err
	}
	jobsSender, err := scans.NewJobQueueSender(producer, cfg.CTQueues.Names())
	if err != nil {
		return err
	}
	creator = scans.NewJobsCreator(st, jobsSender, apiClient, checkMetrics, logger)
	// Try to create possible pending scan checks without having to wait
	// until the next scheduled task runs.
	go func() {
		err := creator.CreateIncompleteScansChecks()
		if err != nil {
			logger.Log("CreateIncompleteScanChecksError", err.Error())
		}
	}()
	// Create the workers that will run each time period.
	sch = scheduler.NewScheduler(logger)
	for i := 0; i < cfg.ChecksCreator.NumOfWorkers; i++ {
		t := &scans.ChecksRunnerTask{ChecksRunnerForTask: creator}
		p := time.Duration(cfg.ChecksCreator.Period) * time.Second
		sch.AddTask(t, p)
	}

	scanService := service.New(logger, st, apiClient, metricsClient, creator, scansNotifier, checksNotifier)

	healthCheckService := service.HealthcheckService{
		DB: db,
	}

	scanEngineSrv := struct {
		endpoint.ScanCreator
		endpoint.ScanGetter
		endpoint.HealthChecker
	}{
		scanService,
		scanService,
		healthCheckService,
	}

	endpoints := endpoint.MakeEndpoints(scanEngineSrv)

	addLoggingMiddleware(endpoints, logger)
	if cfg.Metrics.Enabled {
		addMetricsMiddleware(endpoints, metricsClient)
	}

	mux := http.NewServeMux()
	handlers := transport.AttachRoutes(transport.MakeHandlers(endpoints, logger))
	mux.Handle("/v1/", handlers)
	http.Handle("/", mux)

	// Create checks update state processor.
	p := checkUpdateProcessor(scanService.ProcessScanCheckNotification)

	checkUpdatesProcessorGroup, err := queue.NewUpdateProcessorGroup(cfg.SQS, p, db, logger)
	if err != nil {
		fmt.Printf("Error creating the check events processor: %v", err)
		return err
	}

	errs := make(chan error)
	consumerCtx, finishConsumers := context.WithCancel(context.Background())
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGTERM, syscall.SIGINT)
		<-c
		logger.Log("SIGTERM or SIGINT Received")
		err = errors.New("Received terminate signal")
		errs <- fmt.Errorf("%s", err)
	}()

	schContext, finishSch := context.WithCancel(context.Background())
	var schWG *sync.WaitGroup
	if sch != nil {
		schWG = sch.Start(schContext)
	}

	go func() {
		fmt.Printf("%v\n", banner)
		err = logger.Log("transport", "HTTP", "addr", httpAddr)
		if err != nil {
			// If there is an error when writing to the logger send the
			// error to errs channel which, in turn, will abort the program execution
			errs <- err
		}
		errs <- http.ListenAndServe(httpAddr, nil)
	}()

	// Start sqs consumer.
	go func() {
		checkUpdatesProcessorGroup.StartProcessing(consumerCtx)
	}()
	err = <-errs
	finishConsumers()
	checkUpdatesProcessorGroup.WaitFinish()
	// Finish gracefully the scheduler.
	finishSch()
	if schWG != nil {
		schWG.Wait()
	}
	return logger.Log("exit", err)
}

func addMetricsMiddleware(endpoints *endpoint.Endpoints, metricsClient metrics.Client) {
	metricsMiddleware := middleware.NewMetricsMiddleware(metricsClient)
	withMetrics := metricsMiddleware.Measure()

	endpoints.CreateScan = withMetrics(endpoints.CreateScan)
	endpoints.ListScans = withMetrics(endpoints.ListScans)
	endpoints.GetScan = withMetrics(endpoints.GetScan)
	endpoints.GetScanChecks = withMetrics(endpoints.GetScanChecks)
	endpoints.GetScanStats = withMetrics(endpoints.GetScanStats)
	endpoints.AbortScan = withMetrics(endpoints.AbortScan)
}

func addLoggingMiddleware(endpoints *endpoint.Endpoints, logger log.Logger) {
	withLog := middleware.Logging(logger)

	endpoints.CreateScan = withLog(endpoints.CreateScan)
	endpoints.ListScans = withLog(endpoints.ListScans)
	endpoints.GetScan = withLog(endpoints.GetScan)
	endpoints.GetScanChecks = withLog(endpoints.GetScanChecks)
	endpoints.GetScanStats = withLog(endpoints.GetScanStats)
	endpoints.AbortScan = withLog(endpoints.AbortScan)
}

func newVulcanCoreAPIClient(config checktypesInformer) *client.Client {
	httpClient := newHTTPClient()
	c := client.New(goaclient.HTTPClientDoer(httpClient))
	c.Client.Scheme = config.Schema
	c.Client.Host = config.Host
	return c
}

func newHTTPClient() *http.Client {
	// By now the only way to ensure that every time we make a request
	// to the core we use dns load balancing it's to disable keep alive.
	tr := &http.Transport{DisableKeepAlives: true}
	return &http.Client{Transport: tr}
}

func logWithConfig(cfg logConfig, l log.Logger) (log.Logger, error) {
	t, ok := logLevels[cfg.Level]
	if !ok {
		return nil, fmt.Errorf("log level %s does not exist", cfg.Level)
	}
	return t(l), nil
}
