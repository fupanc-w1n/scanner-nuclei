// Scanner-nuclei: 漏洞扫描 Pod 主程序(架构 §5.4 / §7)
// 使用 nuclei SDK 的全局 QPS + 模板过滤;请求/响应作为漏洞举证写入 MySQL。
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/redis/go-redis/v9"

	scannerconfig "scanner-nuclei/internal/config"
	"scanner-nuclei/internal/mysqldb"
	"scanner-nuclei/internal/worker"
)

func main() {
	cfg, err := scannerconfig.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if cfg.Module != "nuclei" {
		log.Fatalf("expect module=nuclei, got %s", cfg.Module)
	}
	mc, err := cfg.ParseNuclei()
	if err != nil {
		log.Fatalf("parse module_config: %v", err)
	}
	if mc.QPS <= 0 {
		mc.QPS = 200
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr(),
		Password: envOr("DAST_REDIS_PASS", "redis"),
	})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		log.Fatalf("redis ping: %v", err)
	}
	defer rdb.Close()

	mdb, err := mysqldb.Open(cfg.MySQLAddr(), envOr("DAST_DB_USER", "root"), envOr("DAST_DB_PASS", "root"), envOr("DAST_DB_NAME", "dast"))
	if err != nil {
		log.Fatalf("mysql open: %v", err)
	}
	defer mdb.Close()

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() { <-sigCh; cancel() }()

	w := worker.New(cfg, rdb, func(ctx context.Context, msg *worker.BusinessMessage, msgID string) worker.HandlerResult {
		return handleNuclei(ctx, cfg, mc, mdb, msg)
	})
	if err := w.Run(ctx); err != nil {
		log.Fatalf("worker run: %v", err)
	}
}

func handleNuclei(ctx context.Context, cfg *scannerconfig.Config, mc *scannerconfig.NucleiConfig,
	mdb *mysqldb.DB, msg *worker.BusinessMessage) worker.HandlerResult {

	// 查 HTTP/Web 服务目标
	targets, err := mdb.QueryServiceTargets(ctx, msg.TaskID, msg.Hosts, []string{"http", "https", "http-proxy", "http-alt"})
	if err != nil {
		return worker.HandlerResult{Err: fmt.Errorf("query http targets: %w", err)}
	}

	if len(targets) > 0 {
		urls := make([]string, 0, len(targets))
		for _, t := range targets {
			urls = append(urls, fmt.Sprintf("%s:%d", t.Host, t.Port))
		}
		if err := runNucleiScan(ctx, msg.TaskID, msg.TaskPartName, urls, mc.TemplateIDs, mc.QPS, mdb); err != nil {
			return worker.HandlerResult{Err: fmt.Errorf("nuclei scan: %w", err)}
		}
	}

	if err := mdb.SetNucleiStatus(ctx, msg.TaskID, msg.TaskPartName, "completed"); err != nil {
		return worker.HandlerResult{Err: err}
	}
	_, _ = mdb.MarkPartCompletedIfAllDone(ctx, msg.TaskID, msg.TaskPartName)
	return worker.HandlerResult{}
}

// runNucleiScan 复用 demo/DAST.md / rate.md 的实现:LoadTargets(targets, true),WithGlobalRateLimitCtx,WithTemplateFilters。
func runNucleiScan(parentCtx context.Context, taskID uint64, partName string, targets []string, templateIDs []string, qps int, mdb *mysqldb.DB) error {
	if len(targets) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(parentCtx, 30*time.Minute)
	defer cancel()

	home, _ := os.UserHomeDir()
	templateDir := filepath.Join(home, "nuclei-templates")

	opts := []nuclei.NucleiSDKOptions{
		nuclei.WithCatalog(disk.NewCatalog(templateDir)),
		nuclei.DisableUpdateCheck(),
		nuclei.WithGlobalRateLimitCtx(ctx, qps, time.Second),
	}
	if len(templateIDs) > 0 {
		opts = append(opts, nuclei.WithTemplateFilters(nuclei.TemplateFilters{IDs: templateIDs}))
	}

	engine, err := nuclei.NewNucleiEngineCtx(ctx, opts...)
	if err != nil {
		return fmt.Errorf("create engine: %w", err)
	}
	defer engine.Close()
	if err := engine.LoadAllTemplates(); err != nil {
		return fmt.Errorf("load templates: %w", err)
	}
	engine.LoadTargets(targets, true)

	return engine.ExecuteCallbackWithCtx(ctx, func(ev *output.ResultEvent) {
		if ev == nil || !ev.MatcherStatus {
			return
		}
		sev := ev.Info.SeverityHolder.Severity.String()
		if sev == "" {
			sev = "unknown"
		}
		raw, _ := json.Marshal(ev)
		_ = mdb.InsertVulnerability(context.Background(), mysqldb.Vulnerability{
			TaskID:       taskID,
			TaskPartName: partName,
			Host:         ev.Host,
			Port:         0,
			Matched:      ev.Matched,
			TemplateID:   ev.TemplateID,
			Name:         ev.Info.Name,
			Severity:     sev,
			Request:      ev.Request,
			Response:     ev.Response,
			RawEventJSON: string(raw),
		})
	})
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
