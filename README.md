# bsky-list-feeder

## これは何？

Bluesky標準のList機能は、Twitter/XのListと似たように使えるのですが、1) 非公開にできない、2) Listに加えた本人によるポストのみが含まれ、リポストやリプライなどは含まれない、という仕様となっています。1)の方は今のところBlueskyのポリシーに依るもののようなのでどうしようもないとして、2)の方だけでも何とかならないかと思い、作ってみたのがこのbsky-list-feederです[^1]。

[^1]: 初めはfeed generatorが出力する形式の静的なJSONファイルのみを用意すればcustom feedとして利用出来ないか、と思い試してみたのですが、Pagination(cursor/limit)に対応しないとBluesky client/web UI側でまともに表示出来ないことが分かったためdaemonとして動かさざるを得ませんでした。まぁGolangのおかげでメモリ消費は数MBで済みましたので良しとしましょう。

bsky-list-feederはBlueskyのcustom feed generatorの1つですが、以下のような特徴があります。

1. あらかじめ登録したユーザ本人のポストだけでなく、その人がリポストしたポストや登録したユーザ同士で交わされたリプライ(本人宛含む)なども表示されます。
2. 定期的(デフォルト15分毎)に最新のポストを取得しフィードを更新します。
3. GolangによるDocker containerとして動作し、そのイメージサイズは9MBほどととても軽量で、実行時に必要なメモリも数MB程度と極めて少ないです。

なお本リポジトリにはGolangによるbsky-list-feeder本体の他に、Blueskyへcustom feedを登録・削除するのに利用できるpython scriptも置いてあります。

## 使い方

### bsky-list-feederのビルドと起動

bsky-list-feederはdocker composeを使ってビルドから操作まで行えます。デフォルトの場合Dockerfile、docker-compose.ymlファイルのあるディレクトリに `feeds` ディレクトリを作り、その中にさらにfeed IDとして使いたいディレクトリ名でサブディレクトリを作ります。(全体のディレクトリ構成は最後に示します。)

そしてそのfeed ID名のサブディレクトリの中に、リストに含めたい人のDIDを1つずつ改行区切りで格納した `user_did.txt` を置きます。なおWeb UI等で確認出来るユーザのハンドルからDIDを得るのに、同じ場所に置いてある `resolve-handle.sh` が使えます。

また、同じくDockerfile/docker-compose.ymlのあるディレクトリに、Blueskyの自分のアカウントのハンドル、BlueskyのWeb UI等で作成したアプリパスワード(設定→プライバシーとセキュリティ→アプリパスワードで作れます)を以下のように格納しておきます。なおこのファイルは他人から読まれないようモードを `600` などにしておきましょう。

```
BSKY_ID=digitune.bsky.social
BSKY_APPPASSWORD=xxxx-xxxx-xxxx-xxxx
```

`.env` ファイル、`feeds/feedId/user_did.txt` が用意出来たら、bsky-list-feederを起動する準備は整ったので後はビルドしてdaemonとして起動します。

```
$ docker compose build
: (ビルドが正常に完了したら)
$ docker compose up -d
$ docker compose logs -f ← 起動後のlogが確認出来ます。止めるときはCtrl+c
```

bsky-list-feederを起動するとディレクトリ構成は下記のような感じとなります。あ、この時点ではまだ `generator.json` はないかもしれません。

```
$ tree
.
├── .env
├── Dockerfile
├── docker-compose.yml
├── feeds
│   ├── bsky_auth.json
│   └── feedId
│       ├── custom_feed.json
│       ├── generator.json
│       └── user_did.txt
├── go.mod
├── main.go
└── resolve-handle.sh
```

デフォルトではbsky-list-feederは8080番ポートで待ち受けるdaemonとして動作しますので(他のポートを使いたい場合は適宜設定ファイルなどを変更してください)、下記のように `curl` 等を用いて動作確認出来ます。(`feed` query parameterの `%2F` の後に設定したfeed IDを置く。)

```
$ curl 'http://localhost:8080/xrpc/app.bsky.feed.getFeedSkeleton?feed=hogehoge%2FfeedId&limit=1'
{"cursor":"at://did:plc:xxxxxxxx/app.bsky.feed.post/xxxxxxxx","feed":[{"post":"at://did:plc:xxxxxxxx/app.bsky.feed.post/xxxxxxxx"}]}
```

最後に、bsky-list-feederのポート番号(デフォルトでは8080番)を外部のBlueksy側からもアクセス可能なよう、例えばapache mod_proxyによるreverse proxyなどを用いて公開します。

### bsky-list-feederのBlueskyへの登録

動き始めたbsky-list-feederのBlueskyへの登録には、本リポジトリにあるbsky-feed-managerが使えます。こちらを利用するには、まず登録する情報を含んだ `generator.json` ファイルを用意し、feed ID名を持つサブディレクトリ下に置きます。

```
{
  "$type": "app.bsky.feed.generator",
  "did": "did:web:memo.digitune.org",
  "displayName": "My private feed",
  "description": "My private feed (Animals)"
}
```

feed generator固有のDIDを取得して利用する方法の他に(詳細は公式参照)、上記のように自分の持つドメイン名を使ったDIDで登録することも出来、その場合は上記の例ですと下記URLに `did.json` ファイルを置いておく必要があります。serviceEndpointは上記でbsky-list-feederを公開したURLに合わせてください。

```
$ curl https://memo.digitune.org/.well-known/did.json
{
  "@context": [
    "https://www.w3.org/ns/did/v1"
  ],
  "id": "did:web:memo.digitune.org",
  "service": [
    {
      "id": "#bsky_fg",
      "type": "BskyFeedGenerator",
      "serviceEndpoint": "https://memo.digitune.org/xrpc"
    }
  ]
}
```

上記 `generator.json` 、 `did.json` の準備が出来たら、dockerを使って下記のように `create_feed_generator.py` を実行することでbsky-list-feederをBluesky側へ登録出来ます。各ファイルの位置や名前などを変更したい場合は適宜修正してください。

```
(bsky-feed-managerのDockerfile/docker-compose.ymlファイルがあるディレクトリで)
$ docker compose build
$ docker compose run --rm bsky-feed-manager ./create_feed_generator.py public/feedId/generator.json
```

なお `create_feed_generator.py` スクリプトは `generator.json` が置かれたディレクトリ名をfeed IDとして利用しますので注意。

上記が正常に実行出来ればBluesky側へbsky-list-feederが登録出来、自分のアカウントのプロフィール→フィードに現れると思いますので、後はPinするなりして利用してください。

以上です。楽しんでいただければ幸いでした。
