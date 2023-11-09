#

## config

```yml
providers:
    netbox:
        class: octodns_netbox_dns.NetBoxDNSSource
        # Netbox url
        url: "https://some-url"
        # Netbox api token
        token: env/NETBOX_API_KEY
        # Provider 'view' configuration is optional; however, it still can
        # be declared as "null" or with an empty value. If you don't want to
        # set a view in the query, set the value to "false".
        view: false
        # When records sourced from multiple providers, allows provider
        # to replace entries comming from the previous one.
        # Implementation matches YamlProvider's 'populate_should_replace'
        replace_duplicates: false
```
