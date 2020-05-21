# tm-plugin_syslog

TANlock Manager Syslog Plugin

> This is a plugin to send Syslog Events conform to the RFCs
>
> * [rfc5424: The Syslog Protocol](https://tools.ietf.org/html/rfc5424)
> * [rfc6587: Transmission of Syslog Messages over TCP](https://tools.ietf.org/html/rfc6587)
> * [rfc5425: Transport Layer Security (TLS) Transport Mapping for Syslog](https://tools.ietf.org/html/rfc5425)

## Base Config

```json
{
    "useTCP": false,
    "tcpTLS": false,
    "tcpOC": true,
    "tcpNonTransparentFramingChar": "\n",
    "port": 514,
    "host": "255.255.255.255",
    "syslogHostname": "-"
}
```

## Marks on TCP

TCP should use the OctettCount method to frame the message, if `tcpOC` is not used the `tcpNonTransparentFramingChar` will be appended.

## Marks on TLS (untested)

TLS forces the use of OctettCount
