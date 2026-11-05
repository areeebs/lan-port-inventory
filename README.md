# LAN Port Inventory

Take a bounded TCP service snapshot of one private IPv4 address you administer.

The scanner accepts only RFC1918 single-host IPv4 targets. It does not accept CIDRs, resolve names, scan public IPs, send application payloads, or attempt exploitation. It checks at most 32 explicitly selected ports with a short timeout and records open/closed/filtered outcomes for change review.

## Install and run

Requires Python 3.10+. This repository uses only the standard library.

~~~sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
lan-port-inventory 192.168.1.10 --ports 22,443
~~~

Run the offline regression suite:

~~~sh
python -m unittest discover -s tests -v
~~~

## Safety and limits

Use only for systems, domains, data, and accounts you own or are authorized to assess. Provider matches and local detections are leads for analyst review, not proof of compromise or safety. For tools that query an external provider, review the submitted value and provider terms before running it.

## References

- [IANA Service Name and Transport Protocol Port Number Registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)
- This is a narrow inventory helper, not a network discovery scanner.

## License

MIT. See LICENSE.
