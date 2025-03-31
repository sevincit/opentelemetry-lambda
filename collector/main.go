// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/config"
	"net/url"
	"os"

	"github.com/open-telemetry/opentelemetry-lambda/collector/lambdalifecycle"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/open-telemetry/opentelemetry-lambda/collector/internal/lifecycle"
)

var (
	// Version variable will be replaced at link time after `make` has been run.
	Version = "latest"

	// GitHash variable will be replaced at link time after `make` has been run.
	GitHash = "<NOT PROPERLY GENERATED>"
)

func main() {
	versionFlag := flag.Bool("v", false, "prints version information")
	flag.Parse()
	if *versionFlag {
		fmt.Println(Version)
		return
	}

	logger := initLogger()
	logger.Info("Launching OpenTelemetry Lambda extension", zap.String("version", Version))

	user := os.Getenv("OTEL_EXTENSION_USERNAME")
	password_secret := os.Getenv("OTEL_EXTENSION_PASSWORD_SECRET")
	if user != "" && password_secret != "" {
		ctx := context.Background()
		logger.Info("Fetching OTEL_EXTENSION_PASSWORD_SECRET", zap.String("path", password_secret))
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			logger.Error("Unable to load AWS config", zap.Error(err))
			os.Exit(1)
		}
		client := secretsmanager.NewFromConfig(cfg)
		result, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
			SecretId: &password_secret,
		})

		if err != nil {
			logger.Error("Unable to fetch password secret", zap.Error(err))
			os.Exit(1)
		}

		auth_header := fmt.Sprintf("Authorization=Basic %s", base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", user, result.SecretString))))
		headers := os.Getenv("OTEL_EXPORTER_OTLP_HEADERS")
		if headers == "" {
			headers = url.QueryEscape(auth_header)
		} else {
			headers = fmt.Sprintf("%s,%s", headers, url.QueryEscape(auth_header))
		}
		err = os.Setenv("OTEL_EXPORTER_OTLP_HEADERS", headers)
		if err != nil {
			logger.Error("Unable to set OTEL_EXPORTER_OTLP_HEADERS", zap.Error(err))
			os.Exit(1)
		}
	}

	ctx, lm := lifecycle.NewManager(context.Background(), logger, Version)

	// Set the new lifecycle manager as the lifecycle notifier for all other components.
	lambdalifecycle.SetNotifier(lm)

	// Will block until shutdown event is received or cancelled via the context.
	logger.Info("done", zap.Error(lm.Run(ctx)))
}

func initLogger() *zap.Logger {
	lvl := zap.NewAtomicLevelAt(zapcore.InfoLevel)
	envLvl := os.Getenv("OPENTELEMETRY_EXTENSION_LOG_LEVEL")
	// When not set, Getenv returns empty string
	var err error
	if envLvl != "" {
		var userLvl zap.AtomicLevel
		userLvl, err = zap.ParseAtomicLevel(envLvl)
		if err == nil {
			lvl = userLvl
		}
	}

	l := zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), os.Stdout, lvl))

	if err != nil && envLvl != "" {
		l.Warn("unable to parse log level from environment", zap.Error(err))
	}

	return l
}
