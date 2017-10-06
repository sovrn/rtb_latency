# latency_check.py

A simple tool to check the average latency between hosts with HTTP or ICMP and send the results to Graphite. It was created to serve as an alternative to Smokeping.

## System requirements

You must have Python 2.7.x to use this script. Other versions may work, but are untested.

## Configuration

Edit `latency_check.json` to adjust the default values to your liking and add `"protocol": "host"` pairs to the `to_check` list.

## Usage

As root, run:

```python latency_check.py```

There are no command-line flags, all configuration is done in `latency_check.json`. It will assume that `latency_check.json` is in the same directory as the script. Root is required for the Python sockets library to do ICMP things.

## Config format

```
{
    "graphite_host": "hostname.domain.com",
    "graphite_port": 2003,
    "graphite_prefix": "site_latency",
    "check_count": 5,
    "timeout": 1,
    "to_check": [
        {"icmp": "google.com"},
        {"http": "http://google.com"}
    ]
}
```

HTTP checks will also perform ICMP checks, so the inclusion of both above will result in ICMP being done twice.

## Output format

In Graphite, you should expect to see `<prefix>.<source_hostname>.<destination_hostname>.<protocol>` which will be an integer value in milliseconds.
In the case of a failed check, a value of -1 will be sent to Graphite.
Errors will be logged to stdout.

## Installation

To run this periodically, clone this repo into `/opt` and use either the provided Cron or SystemD scripts.

## Credit

This script uses components from https://github.com/samuel/python-ping. It was written for Sovrn by Jeremy McCoy.

## License

This script is MIT licensed as described in the `LICENSE` file
