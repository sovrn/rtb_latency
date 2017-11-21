# latency_check.py

A simple tool to check the average latency between OpenRTB endpoints with an OpenRTB test bid or ICMP and send the results to Graphite. It was created to serve as an alternative to SmokePing.

## System requirements

You must have Python 2.7.x to use this script. Other versions may work, but are untested.
The Python libraries `requests` and `pymysql` must be installed. You can skip pymysql if you are not pulling from a database.

## Usage

As root, run: `python latency_check.py`

There are no command-line flags, all configuration is done in `config.json`.

## Configuration

- Edit `config.json` to adjust the default values to your liking.
- Either configure loading hosts from MySQL or from a JSON file.

### `config.json`

```
{
    "graphite_host": "graphite.example.com",
    "graphite_port": 2003,
    "graphite_prefix": "site_latency",
    "check_count": 3,
    "timeout": 1,
    "load_hosts": [
        {
            "method": "file",
            "path": "hosts_example.json"
        },
        {
            "method": "mysql",
            "mysql_db": "your_db_name",
            "mysql_host": "your_db_host",
            "mysql_user": "your_db_user",
            "mysql_pass": "your_db_password",
            "mysql_query": "select provider_name, region_url from provider_table;"
        }
    ],
    "check_types": [
        "rtb",
        "icmp"
    ],
    "rtb": {
        "bid_ext_pchain": "pchain",
        "bid_site_domain": "example.com",
        "bid_site_page": "http://test.example.com/latency/monitor/test",
        "bid_site_publisher_id": "1",
        "bid_user_id": "your_string",
        "headers": {
            "Content-Type": "application/json",
            "x-openrtb-version": "2.3"
        }
    }
}
```

- `graphite_prefix`: A string to prepend to every Graphite metric line.
- `timeout`: Connection timeout in seconds.
- `check_count`: How many times to check each host and return an average for.
- `rtb`: Can be omitted if you are not performing an RTB check. See `genbid()` function for what these values map to.
- `check_types` specifies the types of checks that will be performed against all hosts. Currently, the options are as follows:
    - `rtb`: Sends a test bid compliant with OpenRTB 2.3
    - `icmp`: Performs an ICMP ping. [Running as root is required for the Python sockets library to do ICMP things](https://stackoverflow.com/questions/1189389/python-non-privileged-icmp).


### `hosts_example.json`

```
{
    "provider": {
       "region": "http://endpoint.example.com"
    }
}
```

## Output format

In Graphite, you should expect to see `<prefix>.<provider>.<remote_region>.<local_host>.<protocol>` which will be an integer value in milliseconds.

In the case of a failed check, a metric with a value of -1 will be sent to Graphite.

Errors will be logged to stdout, which will be captured by syslog or SystemD if you use the supplied scripts.

## Installation

To run this periodically, clone this repo into `/opt` and use the example Ansible playbook/role to deploy it.

If you are not using Ansible, template files for cron and SystemD are under `supplements/`.

## Credit

This script uses components from https://github.com/samuel/python-ping.
It was written for Sovrn by Jeremy McCoy (@MrDrMcCoy).

## License

This script is MIT licensed as described in the `LICENSE` file
