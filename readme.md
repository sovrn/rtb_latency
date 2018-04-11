# rtb_latency.py

A simple tool to check the average latency between hosts with an OpenRTB test bid, HTTP GET request, or ICMP ping, and send the results to Graphite. It was created to serve as an alternative to SmokePing.

## System requirements

- Linux kernel 3.16 or newer. Older versions may work, but are untested.
- You must have Python 2.7.x to use this script. Other versions of Python may work, but are untested.
- A relatively recent `traceroute` that supports MPLS. The script will work without a compatible `traceroute`, but will log errors every time a check exceeds the warning threshold.

## Usage

As root, run: `python rtb_latency.py`
[Root is required for ICMP](https://stackoverflow.com/questions/1189389/python-non-privileged-icmp)

There are no command-line flags, all configuration is done in `config.json`, which should live in the same directory as `rtb_latency.py`.

If you use Grafana for your Graphite dashboards, there is a dashboard template under supplements that you can use.

## Configuration

- Edit `config.json` to adjust the default values to your liking. None of these values are optional.
  - `graphite_host`: FQDN or IP of your Graphite Carbon receiver.
  - `graphite_port`: Set port for your Carbon host if it is not standard.
  - `graphite_prefix`: A string to prepend to every Graphite metric line. Think of it as your Graphite "base path".
  - `check_count`: How many times to check each host and return an average for.
  - `timeout`: Connection timeout in seconds.
  - `threads`: Threads to use for concurrent checking. This should probably match your number of actual system cores.
  - `latency_warn`: Time in seconds (decimal) that, when exceeded, should result in collection of extended network debugging information.
  - `log_level`: Sets the logging level. DEBUG, INFO, WARN, and ERROR are used, but any Python standard logging level will be accepted.
  - `load_hosts`: Defines sources for endpoints to check.
    - `"method": "file"` allows you to load endpoints from a JSON file like `hosts_example.json`.
    - `"method": "mysql"` allows you to load endpoints from a MySQL DB. Your query must return one column as `provider` and an arbitrary number of columns containing a single endpoint URL per row. The endpoint column name should designate the region as `major_minor`, such as `amer_west` or `emea_central`, and must match what you specify for `regions` and `region_filter`. A simple [SQL Alias](https://www.w3schools.com/sql/sql_alias.asp) should be sufficient to accomplish this in your queries if your schema does not match this pattern.
  - `regions`: Define geographic regions that should appear in your host list
    - `major`: The larger geographic area(s) to filter for. This could be like EMEA, amer, APAC, etc., but can be arbitrary so long as it is consistent.
    - `minor`: The sub-region(s) of your geographic area. This could be east, west, north, south, central, etc., but can be arbitrary so long as it is consistent.
  - `region_filter`: Define geographic regions that should be allowed in the latency check if the host list contains more than what any one host should check.
    - `major`: The larger geographic area(s) to filter for. This should be one or more major regions from `regions` as a list.
    - `minor`: The sub-region(s) of your geographic area. This should be one or more minor regions from `regions` as a list. There is a special value of `"star"` that means everything for the given major region.
  - `check_types` specifies the types of checks that will be performed against all hosts. Currently, the options are as follows:
    - `rtb`: Sends a test bid compliant with OpenRTB 2.3.
    - `get`: Performs an HTTP GET request.
    - `icmp`: Performs an ICMP ping.
  - `rtb`: Can be omitted if you are not performing an OpenRTB check. See the `RTB Example Bid` section for what these values map to.
  - `public_ip`: A default set of values if your public IP cannot be detected.
  - `geoip`: A default set of values if your GeoIP cannot be detected.

### Example `config.json`

```json
{
    "graphite_host": "graphite.example.com",
    "graphite_port": 2003,
    "graphite_prefix": "rtb_latency",
    "check_count": 3,
    "timeout": 1,
    "log_level": "INFO",
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
            "mysql_query": "select provider_name as provider, region1_url as amer_west from provider_table;"
        }
    ],
    "check_types": [
        "rtb",
        "get",
        "icmp"
    ],
    "regions": {
        "major": [
            "apac",
            "emea",
            "amer"
        ],
        "minor": [
            "north",
            "south",
            "east",
            "west",
            "central"
        ]
    },
    "region_filter": {
        "major": [
            "amer"
        ],
        "minor": [
            "star"
        ]
    },
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
    },
    "public_ip": "8.8.8.8",
    "geoip": {
        "latitude": 37.4060,
        "longitude": -122.0785,
        "country_code": "USA",
        "region_code": "CA",
        "city": "Mountain View",
        "zip_code": "94043"
    }
}
```

### Example `hosts.json`

```json
{
    "provider": {
       "major_minor": "http://endpoint.example.com"
    }
}
```

### RTB Example Bid

```json
{
   "imp": [
      {
         "banner": {
            "h": 600,
            "pos": 3,
            "w": 160
         },
         "id": "1",
         "secure": 0
      }
   ],
   "ext": {
      "pchain": "pchain"
   },
   "device": {
      "geo": {
         "city": "Boulder",
         "zip": "80309",
         "country": "US",
         "region": "CO",
         "lon": -105.2706,
         "lat": 40.015,
         "type": 2
      },
      "dnt": 0,
      "devicetype": 2,
      "os": "OS X",
      "language": "en",
      "ip": "67.129.88.18",
      "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36",
      "osv": "10.12.6"
   },
   "user": {
      "id": "your_string"
   },
   "test": 1,
   "at": 2,
   "id": "61e0260f-9656-40b2-b9d7-a336d3aeb429",
   "site": {
      "publisher": {
         "id": "1"
      },
      "domain": "example.com",
      "id": "1",
      "page": "http://test.example.com/latency/monitor/test"
   }
}
```

## Graphite output format

In Graphite, you should expect to see `<prefix>.<provider>.<region>.<endpoint_ip>.<local_host>.<protocol>` which will be an integer value in milliseconds.

In the case of a failed check, a metric with a value of -1 will be sent to Graphite.

Information will be logged to stdout, which will be captured by syslog or SystemD if you use the supplied scripts under `supplements`. On latencies over 100ms or a timed out connection, the script will attempt to gather some additional networking traces to assist with troubleshooting, which will be logged at the WARN level.

## Installation

To run this periodically, clone this repo into `/opt` and use the example Ansible playbook/role under `supplements/` to deploy it.

If you are not using Ansible, template files for cron and SystemD are under `supplements/`.

## Credits

This script uses components from various Python projects, which are present here as submodules. Refer to them for licensing and credits
It was written for Sovrn Holdings by Jeremy McCoy (@MrDrMcCoy).

## License

This script is Apache 2.0 licensed as described in the `LICENSE` file
