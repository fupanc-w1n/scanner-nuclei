# scanner-nuclei: 漏洞扫描 Pod 镜像
# Nuclei SDK 较大,首次构建依赖拉取耗时较长。GHA 上默认 GOPROXY 工作良好。
# 容器运行时 nuclei 会自动同步 ~/nuclei-templates;如需预置模板库,
# 可在 runtime stage 加 RUN git clone https://github.com/projectdiscovery/nuclei-templates /root/nuclei-templates
#
# Pod 运行时支持下列环境变量(K8s Deployment 可通过 env 字段覆盖):
#   DAST_CONFIG       默认 /app/config/config.json   ConfigMap 挂载点
#   DAST_DB_USER      默认 root                       MySQL 账号
#   DAST_DB_PASS      代码默认 root                   MySQL 密码,可通过 ENV 覆盖
#   DAST_DB_NAME      默认 dast                       MySQL 数据库
#   DAST_REDIS_PASS   默认 redis                      Redis 密码(为空表示无密码)
# MySQL/Redis 地址、端口由 ConfigMap 中的 scheduler.internal_ip / mysql_port / redis_port 决定。

FROM golang:1.25-alpine AS builder
WORKDIR /src
# ENV GOPROXY=https://goproxy.cn,direct
RUN apk add --no-cache git
COPY main.go .
COPY internal ./internal
RUN go mod init scanner-nuclei \
 && go mod tidy \
 && CGO_ENABLED=0 GOOS=linux go build -o /out/scanner-nuclei .

FROM alpine:latest
RUN apk add --no-cache ca-certificates tzdata git
WORKDIR /app
COPY nuclei-templates /root/nuclei-templates
COPY --from=builder /out/scanner-nuclei /app/scanner-nuclei
ENV DAST_CONFIG=/app/config/config.json \
    DAST_DB_USER=root \
    DAST_DB_PASS=fupanC@123 \
    DAST_DB_NAME=dast \
    DAST_REDIS_PASS=redis \
    TZ=Asia/Shanghai
ENTRYPOINT ["/app/scanner-nuclei"]
