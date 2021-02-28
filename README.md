# Hetzner Load Balancer ACME-DNS

[![Go Report Card](https://goreportcard.com/badge/github.com/pirsch-analytics/hetzner-lb-acmedns)](https://goreportcard.com/report/github.com/pirsch-analytics/hetzner-lb-acmedns)
<a href="https://discord.gg/fAYm4Cz"><img src="https://img.shields.io/discord/739184135649886288?logo=discord" alt="Chat on Discord"></a>

A service to automatically update Letsencrypt SSL certificates on the Hetzner load-balancer using [ACME-DNS](https://github.com/joohoi/acme-dns).

## Installation

*WIP*

## Usage

*WIP*

```json
[
    {
        "email": "john@doe.com",
        "acmedns": {
            "username": "",
            "password": "",
            "full_domain": "",
            "sub_domain": "",
            "domains": ["example.com", "*.example.com"]
        },
        "hetzner": {
            "name": "test-cert",
            "labels": {"foo": "bar"}
        }
    }
]
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

MIT
