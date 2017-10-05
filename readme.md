# latency_check.py

A simple tool to check the average latency between hosts with HTTP or ICMP and send the results to Graphite. It was created to serve as an alternative to Smokeping.

## System requirements

You must have Python 2.7.x to use this script. Other versions may work, but are untested.

## Configuration

Edit `latency_check.json` to adjust the default values to your liking and add `"protocol": "host"` pairs to the `to_check` list.

## Usage

As root, run:

```python latency_check.py```

There are no configuration options. It will assume that `latency_check.json` is in the same directory as the script. Root is required for the Python sockets library to do ICMP things.

## Installation

To run this periodically, clone this repo into `/opt` and use either the provided Cron or SystemD scripts.

## To-Do
- Make `http_latency` obey the timeout value.

## Credit

This script uses components from https://github.com/samuel/python-ping. It was written for Sovrn by Jeremy McCoy.

## License

This script is MIT licensed as described in the `LICENSE` file
