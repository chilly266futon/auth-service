package config

import (
	"time"

	"go.uber.org/zap"

	"github.com/chilly266futon/exchange-shared/pkg/config"
)

type Config struct {
	config.BaseConfig
}

func Load(path string, logger *zap.Logger) *Config {
	base := config.LoadBase(path, "AUTH", logger)

	if base.Server.Host == "" {
		base.Server.Host = "0.0.0.0"
	}
	if base.Server.Port == 0 {
		base.Server.Port = 50053
	}
	if base.Server.ShutdownTimeout == 0 {
		base.Server.ShutdownTimeout = 30 * time.Second
	}

	return &Config{BaseConfig: *base}
}

type ServerConfig struct {
	Host               string        `mapstructure:"host"`
	Port               int           `mapstructure:"port"`
	MetricsPort        int           `mapstructure:"metrics_port"`
	ShutdownTimeout    time.Duration `mapstructure:"shutdown_timeout"`
	HealthEnabled      bool          `mapstructure:"health_enabled"`
	HealthCheckTimeout time.Duration `mapstructure:"health_check_timeout"`
}
