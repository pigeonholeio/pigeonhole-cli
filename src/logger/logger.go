package logger

import (
	"os"

	"github.com/sirupsen/logrus"
)

var Log *logrus.Logger

// Initialize the logger
func InitLogger(logLevel logrus.Level) {
	Log = logrus.New()

	// Set the output to standard output (could also be a file)
	Log.Out = os.Stdout

	// Set the log level (e.g., Info, Warn, Error)

	// Set the formatter (e.g., TextFormatter, JSONFormatter)
	Log.SetFormatter(&logrus.TextFormatter{
		DisableTimestamp:       true,
		DisableLevelTruncation: true,
		TimestampFormat:        "2006-01-02 15:04:05", // Customize timestamp format
	})

	Log.SetReportCaller(false)
	Log.SetLevel(logLevel)

}
