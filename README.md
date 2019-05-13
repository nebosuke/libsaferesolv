# libsaferesolv.so for Linux

getaddrinfo(3) をラップして、任意のプロセスが発行する getaddrinfo(3) の呼び出しキャプチャし、その結果を最大100件キャッシュする。
通常は、オリジナルの glibc の実装の結果をそのまま返すが、DNSサーバーの停止、空のゾーン情報、/etc/hostsの破損など、リゾルバがIPアドレスを解決できない状況においても、24時間以内のもっとも新しい成功した結果で getaddrinfo(3) が結果を返すようになる。

## 使い方
getaddrinfo(3) をガードしたいプロセスの起動時に、LD_PRELOAD で libsaferesolv.so を読み込むように指定する。
```
LD_PRELOAD=/usr/local/lib/libsaferesolv.so java -jar app.jar
```

## Dockerコンテナ内での利用
LD_PRELOAD のメカニズムは、glibc特有の方法なので、alipneなど別のlibcを持つイメージではうまく動かない。
Java実行環境の場合、```openjdk:8-jre-slim``` はOKだが、```openjdk:8-jre-alpine``` ではダメ。

## ビルド方法
```
$ git clone https://github.com/nebosuke/libsaferesolv.git
$ cd libsaferesolv
$ make
```

## 背景
- ストレージやDBなど、クラウドで利用可能なマネージドサービスの可用性のために、DNSのTTL値は短く設定されている。
- 利用するアプリ側でも Java などホスト名解決結果をキャッシュするアーキテクチャーでは、名前解決のキャッシュを無効化するか、十分に小さい時間を指定することが求められている。
    - Javaの場合、一般に ```-Dnetworkaddress.cache.ttl=0 -Dnetworkaddress.cache.negative.ttl=0``` を指定する
- このため DNS の設定をミスるなど何か設定に問題が起きたとき、即座にすべてのサービスダウンが引き起こされてしまう。
- ユースケースとしてIPアドレスが解決できることが期待できるときは、名前解決に失敗したときだけ、前回に成功したときの値を返すような getaddrinfo(3) が欲しい。

## 別のやり方
- dnsmasq を導入し、実行環境ごとに名前解決自体を堅牢にする方法もある。
