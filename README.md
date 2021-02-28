# Hetzner Load Balancer ACME-DNS

[![Go Report Card](https://goreportcard.com/badge/github.com/pirsch-analytics/hetzner-lb-acmedns)](https://goreportcard.com/report/github.com/pirsch-analytics/hetzner-lb-acmedns)
<a href="https://discord.gg/fAYm4Cz"><img src="https://img.shields.io/discord/739184135649886288?logo=discord" alt="Chat on Discord"></a>

A service to automatically update Letsencrypt SSL certificates on the Hetzner load-balancer using [joohoi/acme-dns](https://github.com/joohoi/acme-dns).

## Installation

Please see the [docker-compose.yml](docker-compose.yml) for reference. Before you can start using the service, you need to have created a project on Hetzner cloud, an API token, as well as a acme-dns server. You can then configure it using the following environment variables:

| Variable | Description |
| - | - |
| HLBA_LOG_LEVEL | debug, info |
| HLBA_CA_URL | The URL to your CA. `https://acme-staging-v02.api.letsencrypt.org/directory` for Letsencrypt staging for example. |
| HLBA_ACMEDNS_URL | The URL to your acme-dns server. `https://auth.example.com/` for example. |
| HLBA_HETZNER_API_TOKEN | Your Hetzner API token (with write access). |

Make sure you mount the `data` directory, as it is required for configuring certificate requests and configuration files created by the server.

## Usage

To configure certificate requests, create a file called `cert-requests.json` inside the `data` directory.

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
            "labels": {"foo": "bar"},
            "lb_name": "test-lb",
            "lb_port": 443
        }
    },
    # ...
]
```

Note that you have to create an acme-dns user before you can start using this service. Enter the details for each certificate/load-balancer you would like to update. The `labels` option for the certificate in the `hetzner` section is optional. The certificates will be automatically updated once a day and on startup if required (after two months).

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

MIT
