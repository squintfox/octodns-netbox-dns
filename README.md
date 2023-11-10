# netbox-plugin-dns source for octodns

> Works with https://github.com/peteeckel/netbox-plugin-dns

## config

```yml
providers:
    config:
        class: octodns_netbox_dns.NetBoxDNSSource
        # Netbox url
        # [mandatory, default=null]
        url: "https://some-url"
        # Netbox api token
        # [mandatory, default=null]
        token: env/NETBOX_API_KEY
        # View of the zone. Can be either a string (the view name) or "null"
        # to only query zones without a view. Set to false to ignore views
        # [optional, default=false]
        view: false
        # When records sourced from multiple providers, allows provider
        # to replace entries coming from the previous one.
        # Implementation matches YamlProvider's 'populate_should_replace'
        # [optional, default=false]
        replace_duplicates: false
        # Make CNAME, MX and SRV records absolute if they are missing the trailing "."
        # [optional, default=false]
        make_absolute: false
```

## install

### via pip

```bash
pip install octodns-netbox-dns@git+https://github.com/olofvndrhr/octodns-netbox-dns.git@main
```

### via pip + `requirements.txt`

add the following line to your requirements file

```bash
octodns-netbox-dns@git+https://github.com/olofvndrhr/octodns-netbox-dns.git@main
```
