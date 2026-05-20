package main

import (
	"context"
	"time"

	"buf.build/go/protovalidate"
	"go.uber.org/zap"
	"google.golang.org/grpc/reflection"

	"github.com/chilly266futon/auth-service/internal/config"
	"github.com/chilly266futon/auth-service/internal/domain"
	"github.com/chilly266futon/auth-service/internal/service"
	userstorage "github.com/chilly266futon/auth-service/internal/storage/postgres"
	tokenstorage "github.com/chilly266futon/auth-service/internal/storage/redis"
	transport "github.com/chilly266futon/auth-service/internal/transport/grpc"
	authmigrations "github.com/chilly266futon/auth-service/migrations"

	authv1 "github.com/chilly266futon/exchange-service-contracts/gen/pb/auth"

	"github.com/chilly266futon/exchange-shared/pkg/auth"
	"github.com/chilly266futon/exchange-shared/pkg/grpcutil"
	"github.com/chilly266futon/exchange-shared/pkg/health"
	"github.com/chilly266futon/exchange-shared/pkg/infra"
	"github.com/chilly266futon/exchange-shared/pkg/interceptors"
	"github.com/chilly266futon/exchange-shared/pkg/logger"
	"github.com/chilly266futon/exchange-shared/pkg/postgres"
	"github.com/chilly266futon/exchange-shared/pkg/telemetry"
)

func main() {
	l := logger.New()
	defer func() {
		if err := l.Sync(); err != nil {
			l.Error("failed to sync logger", zap.Error(err))
		}
	}()

	cfg := config.Load("config.yaml", l)

	l.Info("starting auth-service", zap.Int("port", cfg.Server.Port))

	// Telemetry (трассировка + Prometheus метрики)
	shutdownTelemetry, metricsHandler, err := telemetry.Setup("auth-service", l)
	if err != nil {
		l.Fatal("failed to setup telemetry", zap.Error(err))
	}
	defer shutdownTelemetry()

	// Кастомные метрики
	m, err := infra.InitMetrics("auth-service")
	if err != nil {
		l.Fatal("failed to create metrics", zap.Error(err))
	}

	// Postgres
	dbPool, err := infra.InitPostgres(cfg.Database, l)
	if err != nil {
		l.Fatal("failed to connect to postgres", zap.Error(err))
	}
	defer dbPool.Close()

	if err := postgres.RunMigrations(dbPool, authmigrations.FS, "."); err != nil {
		l.Fatal("migrations failed", zap.Error(err))
	}

	userStorage := userstorage.NewUserStorage(dbPool)

	// Redis
	redisClient := infra.InitRedis(cfg.Redis, l)
	defer func() {
		if err := redisClient.Close(); err != nil {
			l.Error("failed to close redis client", zap.Error(err))
		}
	}()

	tokenStorage := tokenstorage.NewTokenStorageFromClient(redisClient)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tokenStorage.Close(ctx); err != nil {
			l.Error("failed to close redis connection", zap.Error(err))
		}
	}()

	// JWT
	jwtManager := domain.NewJWTManager(cfg.JWT.Secret)      // для генерации токенов
	jwtValidator := auth.NewJWTValidator(cfg.JWT.Secret, l) // для проверки токенов в middleware

	useCase := service.NewAuthUseCase(userStorage, tokenStorage, jwtManager, jwtValidator, m, l)

	validatorInstance, err := protovalidate.New()
	if err != nil {
		l.Fatal("failed to initialize validator", zap.Error(err))
	}

	interceptorsChain, rateLimiter := interceptors.NewInterceptorChain(
		l,
		m,
		cfg.RateLimit,
		cfg.Logger,
		jwtValidator,
		validatorInstance,
		[]string{"/auth.v1.AuthService/Register", "/auth.v1.AuthService/Login"},
		cfg.OperationTimeouts,
	)
	defer rateLimiter.Stop() // Корректно завершаем клинап пользователей

	grpcServer, err := grpcutil.NewServer(
		grpcutil.ServerConfig{
			Host:            cfg.Server.Host,
			Port:            cfg.Server.Port,
			ShutdownTimeout: cfg.Server.ShutdownTimeout,
		}, l, interceptorsChain...,
	)
	if err != nil {
		l.Fatal("failed to create server", zap.Error(err))
	}
	authv1.RegisterAuthServiceServer(grpcServer.GRPCServer(), transport.NewAuthServer(useCase))

	if cfg.Server.HealthEnabled {
		healthTimeout := cfg.Server.HealthCheckTimeout
		if healthTimeout == 0 {
			healthTimeout = 2 * time.Second
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		health.RegisterHealthServer(
			ctx,
			grpcServer.GRPCServer(),
			l,
			"auth_v1.AuthService",
			map[string]func(context.Context) error{
				"postgres": func(ctx context.Context) error { return health.CheckPostgresHealth(ctx, userStorage.DB()) },
				"redis":    func(ctx context.Context) error { return health.CheckRedisHealth(ctx, redisClient) },
			},
			30*time.Second,
			healthTimeout,
		)
	}

	reflection.Register(grpcServer.GRPCServer())

	// HTTP сервер для /metrics (Prometheus)
	metricsCtx, metricsCancel := context.WithCancel(context.Background())
	defer metricsCancel()
	grpcServer.StartMetricsServer(metricsCtx, cfg.Server.MetricsPort, metricsHandler)

	// Start с встроенным graceful shutdown
	if err := grpcServer.Start(); err != nil {
		l.Fatal("server error", zap.Error(err))
	}
}
