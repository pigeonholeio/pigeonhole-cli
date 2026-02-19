package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/pigeonholeio/common/utils"
	"github.com/pigeonholeio/pigeonhole-cli/auth"
	"github.com/pigeonholeio/pigeonhole-cli/config"
	"github.com/pigeonholeio/pigeonhole-cli/credentialstore"
	"github.com/pigeonholeio/pigeonhole-cli/sdk"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/Masterminds/semver/v3"
)

var (
	timeoutSec       int
	PigeonHoleClient sdk.ClientWithResponses
	GlobalCtx        context.Context
	PigeonHoleConfig config.PigeonHoleConfig
	ContextCancel    context.CancelFunc
)

var rootCmd = &cobra.Command{
	Use:           "pigeonhole",
	Short:         "Sending secrets securely.",
	SilenceErrors: true,
	Long:          `This command will display the size of a directory with several different options.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		SetLogger()
		GlobalCtx, ContextCancel = context.WithTimeout(context.Background(), 60*time.Second)
		PigeonHoleClient = *sdk.PigeonholeClient(&PigeonHoleConfig, Version)
		if cmd.Annotations["skip-pre-run"] == "true" {
			logrus.Debugln("skipping-pre-run for: ", cmd.CommandPath())
			return
		}

		// Validate token locally and refresh if needed
		err := auth.ValidateAndRefreshToken(GlobalCtx, &PigeonHoleConfig, fullConfigPath)
		if err != nil {
			logrus.Debugf("Token validation failed: %v", err)
			fmt.Printf("🛡️ Authentication Error: %v\n", err)
			os.Exit(0)
		}

		// Sync local keys with remote API after successful auth
		if viper.GetString("auth.accesstoken") != "" {
			syncErr := auth.SyncKeysWithRemote(GlobalCtx, &PigeonHoleConfig, &PigeonHoleClient)
			if syncErr != nil {
				logrus.Debugf("Key sync failed: %v", syncErr)
				// Non-blocking - continue with command execution
			}
		}

		if utils.KeysExist() != true && viper.GetString("auth.accesstoken") != "" {
			fmt.Println("WARNING: No keys exist yet! Set one with pigeonhole-cli keys init")
		}
	},
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())

}

var verbose bool
var cfgFile string
var v *viper.Viper

func sameMajorMinor(server, client string) bool {
	logrus.Debugf("server version: %s, client version: %s", server, client)
	sv1, err := semver.NewVersion(server)
	if err != nil {
		return false
	}

	sv2, err := semver.NewVersion(client)
	if err != nil {
		return false
	}

	return sv1.Major() == sv2.Major() && sv1.Minor() == sv2.Minor()
}

func init() {

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.pigeonhole/config.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Display more verbose output in console output. (default: false)")
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
	logrus.Debugf("Called InitConfig")
	InitConfig()
}

var configPath, fullConfigPath, configName, configType string

func InitConfig() {
	v = viper.NewWithOptions(viper.KeyDelimiter("::"))
	logrus.Debugf("Called InitConfig")
	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			logrus.Fatalf("could not determine home directory: %v", err)
		}
		configPath = fmt.Sprintf("%s/.pigeonhole", home)
		os.MkdirAll(configPath, 0o700)
		configType = "yaml"
		configName = "config"
		fullConfigPath = fmt.Sprintf("%s/%s.%s", configPath, configName, configType)
		v.AddConfigPath(configPath)
		v.SetConfigName(configName)
		v.SetConfigType(configType)
		viper.Set("fullConfigPath", fullConfigPath)
	}

	// sensible defaults
	v.SetDefault("api::url", "https://api.pigeono.io/v1")
	v.SetDefault("log::level", "info")

	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		logrus.Debugf("Could not read config file: %v", err)
	}
	if err := v.Unmarshal(&PigeonHoleConfig); err != nil {
		logrus.Fatalf("Unable to decode into struct: %v", err)
	}

	// Load credentials from secure storage (keyring/file) after loading config
	// This ensures credentials are loaded from the most secure available storage
	loadCredentialsFromStore(&PigeonHoleConfig, &fullConfigPath)
}

func SetLogger() {
	logrus.SetFormatter(&logrus.TextFormatter{
		TimestampFormat: "2006-01-02T15:04:05Z07:00", // ISO8601 Format
	})
	logrus.SetReportCaller(false)
	if verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}
}

// loadCredentialsFromStore loads credentials from secure storage (keyring/file)
// credentialstore is PRIMARY - if it initializes successfully, load ONLY from it
// If credentialstore fails, fall back to credentials already loaded from config file
func loadCredentialsFromStore(cfg *config.PigeonHoleConfig, fullConfigPath *string) {
	// Skip if no config
	if cfg == nil {
		return
	}

	// Try to initialize credential store
	store, err := credentialstore.NewStore(fullConfigPath)
	if err != nil {
		logrus.Debugf("Credential store not available, falling back to config file credentials: %v", err)
		// Credentials remain as loaded from config file - this is the fallback path for containers
		return
	}

	// Credential store is available - load ONLY from it and override config file values
	storeBackend := store.Backend()
	logrus.Debugf("Credential store available (%s), loading credentials from it", storeBackend)

	// Try to load active user from credential store
	activeUser, err := store.GetActiveUser()
	if err == nil && activeUser != "" {
		logrus.Debugf("Loaded active user from %s: %s", storeBackend, activeUser)
		email := activeUser

		// Load tokens from credential store
		if err := cfg.LoadTokensFromStore(store, email); err != nil {
			logrus.Debugf("Could not load tokens from credential store: %v", err)
			// Credentials remain as loaded from config file
		} else {
			logrus.Debugf("Loaded tokens from %s for %s", storeBackend, email)
		}

		// Load GPG keys from credential store
		if identity, err := cfg.LoadGPGKeysFromStore(store, email); err != nil {
			logrus.Debugf("Could not load GPG keys from credential store: %v", err)
		} else if identity != nil {
			if cfg.Identity == nil {
				cfg.Identity = make(map[string]*config.UserIdentity)
			}
			cfg.Identity[email] = identity
			logrus.Debugf("Loaded GPG keys from %s for %s", store.Backend(), email)
		}
	} else {
		// Fall back to user email from config
		logrus.Debugf("No active user set, falling back to user email from config")
		email, err := cfg.GetUserEmail()
		if err != nil || email == "" {
			logrus.Debugf("Could not determine user email for credential loading: %v", err)
			return
		}

		logrus.Debugf("Using user email from config: %s", email)

		// Load tokens from credential store
		if err := cfg.LoadTokensFromStore(store, email); err != nil {
			logrus.Debugf("Could not load tokens from credential store: %v", err)
			// Credentials remain as loaded from config file
		} else {
			logrus.Debugf("Loaded tokens from %s for %s", storeBackend, email)
		}

		// Load GPG keys from credential store
		if identity, err := cfg.LoadGPGKeysFromStore(store, email); err != nil {
			logrus.Debugf("Could not load GPG keys from credential store: %v", err)
		} else if identity != nil {
			if cfg.Identity == nil {
				cfg.Identity = make(map[string]*config.UserIdentity)
			}
			cfg.Identity[email] = identity
			logrus.Debugf("Loaded GPG keys from %s for %s", store.Backend(), email)
		}
	}
}
