# dns_relay

This is a simple DNS relay server written in C.

## Prerequisites

- gcc (have tested on 15.2.1)
- make (have tested on 4.4.1)

```bash
sudo apt update
sudo apt install gcc make
```

## Build

This project use Makefile to build

```bash
make
```

## Run

(require sudo privilege for port 53)

```bash
make run
```

## Test

The host file is in `./hosts`, you can modify as your will.

```bash
nslookup www.test1.com 127.0.0.1
```
