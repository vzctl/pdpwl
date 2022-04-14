# PDP Create Context iptables matcher

This is an iptables module and it can match Caller-Station-Id attribute from PDP Create Context request. It also implements whitelisting by Station-Id ranges. This is open source and released under the terms of the GNU General Public License v2

## Usage

pdp match options for PDP Create Context requests:
```
 --pdp-any                 Match any request
 --pdp-reserved            Match hardcoded list of station ids
 --pdp-station-id num      Match particular Calling-Station-ID
```

## Example

```
iptables -A INPUT -m pdp --pdp-reserved -j ACCEPT
iptables -A INPUT -m pdp --pdp-station-id  111111111111 -j ACCEPT
iptables -A INPUT -m pdp --pdp-any -j DROP
```

## Notes

You should edit whitelist.c to change harcoded list of Station-Id ranges
