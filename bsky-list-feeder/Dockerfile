# Step 1: ビルドステージ
# Alpine Linuxベースの軽量なGoイメージを使用
FROM golang:1.24-alpine AS builder

# 作業ディレクトリの設定
WORKDIR /app

# go.modとmain.goをコピー
COPY go.mod .
COPY main.go .

# 依存関係を解決・ダウンロード
RUN go mod tidy
RUN go mod download

# プログラムのビルド
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o bsky-list-feeder main.go

# CA証明書をインストールし、最終イメージにコピーするために一時的な場所に配置
RUN apk --no-cache add ca-certificates && \
    cp /etc/ssl/certs/ca-certificates.crt /usr/local/share/ca-certificates/ca-certificates.crt

# ユーザ＆グループを作成
RUN addgroup -S -g 1000 feeder
RUN adduser -S -u 1000 -G feeder feeder

# Step 2: 最終実行ステージ
# scratchはOSを含まない最小のイメージです
FROM scratch

# ステージ1で作成したユーザとグループ情報をコピーする
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

# ビルドしたバイナリを最終イメージにコピー
COPY --from=builder /app/bsky-list-feeder /app/bsky-list-feeder

# ビルドステージからCA証明書を最終イメージにコピー
COPY --from=builder /usr/local/share/ca-certificates/ca-certificates.crt /etc/ssl/certs/

# 作業ディレクトリの設定
WORKDIR /app

# 実行ユーザの設定
USER feeder

# 8080ポートを公開
EXPOSE 8080

# コンテナ起動時に実行するコマンド
CMD ["/app/bsky-list-feeder"]
