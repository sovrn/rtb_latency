# latency_check.py

A simple tool to check the average latency between hosts with HTTP or ICMP and send the results to Graphite. It was created to serve as an alternative to SmokePing.

## System requirements

You must have Python 2.7.x to use this script. Other versions may work, but are untested.

## Configuration

Edit `latency_check.json` to adjust the default values to your liking and add `{"protocol": "host"},` pairs to the `to_check` list.

## Usage

As root, run: `python latency_check.py latency_check.json`

The path to the config file is required.
There are no other command-line flags, all configuration is done in `latency_check.json`.

[Running as root is required for the Python sockets library to do ICMP things](https://stackoverflow.com/questions/1189389/python-non-privileged-icmp).

## Config format

```
{
    "graphite_host": "graphite.example.com",
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

The `timeout` is in seconds, and `check_count` is how many times to check each host and return an average for.
HTTP check entries will also perform ICMP checks, so the inclusion of both as above will result in ICMP being done twice.

## Output format

In Graphite, you should expect to see `<graphite_prefix>.<source_hostname>.<destination_hostname>.<protocol>` which will be an integer value in milliseconds.

In the case of a failed check, a value of -1 will be sent to Graphite.

Errors will be logged to stdout, which will be captured by syslog or SystemD if you use the supplied scripts.

## Installation

To run this periodically, clone this repo into `/opt` and use the example Ansible playbook/role to deploy it.

If you are not using Ansible, template files for cron and SystemD are under `supplements/`.

## Credit

This script uses components from https://github.com/samuel/python-ping.
It was written for Sovrn by Jeremy McCoy (@MrDrMcCoy).

## License

This script is MIT licensed as described in the `LICENSE` file
