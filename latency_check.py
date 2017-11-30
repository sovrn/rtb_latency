#!/usr/bin/python

import itertools
import json
import logging
import os
import ping
import re
import requests
import socket
import sys
import time
import urllib2
import uuid

logging.basicConfig(format='%(filename)s | %(levelname)s | %(funcName)s | %(message)s')
logger = logging.getLogger(__file__)


def genconfig():
    """
    Reads config from file and further populates config with dynamic data.

    :return: config as dict
    """
    # Open config file
    logger.debug('Loading config file...')
    try:
        script_dir = os.path.dirname(os.path.realpath(__file__))
        with open(script_dir + '/config.json', 'r') as config_file:
            config = json.loads(config_file.read())
    except Exception as ex:
        logger.exception('Trouble opening config file.')
        sys.exit(1)
    # Get public IP
    logger.debug('Requesting public IP from ipify.org...')
    try:
        pubiprequest = urllib2.urlopen(url='https://api.ipify.org')
        config['public_ip'] = pubiprequest.read()
        pubiprequest.close()
    except Exception as ex:
        logger.exception('Error getting public IP from ipify.org.')
    # Get GeoIP info
    logger.debug('Requesting GeoIP from freegeoip.net...')
    try:
        geoiprequest = urllib2.urlopen(url='http://freegeoip.net/json/' + config['public_ip'])
        config['geoip'] = json.loads(geoiprequest.read())
        geoiprequest.close()
    except Exception as ex:
        logger.exception('Error getting GeoIP from freegeoip.net.')
    return config


config = genconfig()
logger.setLevel(logging.getLevelName(config['log_level']))


def extract_hostname(string):
    """
    Extract FQDN or IP from a full URL

    :param string: A URL as a string
    :return: FQDN or IP as a string
    """
    if '//' in string:
        return re.findall(r'(?<=//)[\w.\-]+', string)[0]
    else:
        return string


def graphite_safe(string):
    """
    Sanitizes a string so that it can be used as part of a Graphite line.
    It does this by replacing non-alphanumeric characters with underscores.

    :param string: Your string to sanitize
    :return: Your sanitized string
    """
    # Convert whitespaces to underscores
    string = re.sub(r'\s', '_', string)
    # Convert non-alphanumeric characters to underscores
    string = re.sub(r'[^\w]', '_', string)
    # Collapse repeating characters into one
    string = ''.join(ch for ch, _ in itertools.groupby(string))
    return string


def build_host_dict():
    """
    Generates host list from sources defined in config file.
    Example output:
        {
            'provider_name': {
                'region_name': 'url',
                ...
            },
            ...
        }

    :return: Providers as dict
    """
    checks = {}
    for id, source in enumerate(config['load_hosts']):
        if config['load_hosts'][id]['method'] == 'file':
            try:
                filepath = config['load_hosts'][id]['path']
                logger.debug('Loading hosts from JSON file: ' + filepath)
                checks.update(json.loads(open(filepath, 'r').read()))
            except Exception as ex:
                logger.exception('Could not open JSON host file: ' + filepath)
        elif config['load_hosts'][id]['method'] == 'mysql':
            try:
                logger.debug('Loading hosts from MySQL DB.')
                import pymysql
                mysql_db = config['load_hosts'][id]['mysql_db']
                mysql_query = config['load_hosts'][id]['mysql_query']
                mysql_conn = pymysql.cursors.DictCursor(pymysql.connect(
                    host=config['load_hosts'][id]['mysql_host'],
                    user=config['load_hosts'][id]['mysql_user'],
                    passwd=config['load_hosts'][id]['mysql_pass'],
                    database=mysql_db
                ))
                result_count = mysql_conn.execute(mysql_query)
                result_dict = mysql_conn.fetchall()
                for id, row in enumerate(result_dict):
                    provider = result_dict[id]['provider_name']
                    if provider not in checks:
                        checks[provider] = {}
                    for region in result_dict[id]:
                        if 'http' in result_dict[id][region]:
                            checks[provider][region] = result_dict[id][region]
            except Exception as ex:
                logger.exception('Could not load hosts from MySQL.')
        else:
            logger.error('Unknown source type for hosts: ' + source)
        # Some of the providers gathered from MySQL may be empty, so we should remove them.
        logger.debug('Removing empty keys from host dict...')
        emptykeys = []
        for key in checks:
            if checks[key] == {}:
                emptykeys.append(key)
        for key in emptykeys:
            del checks[key]
    return checks


def genbid():
    """
    Generates a unique test bid compliant with OpenRTB 2.3

    :return: JSON body as string
    """
    return json.dumps({
        "ext": {
            "pchain": config['rtb']['bid_ext_pchain']
        },
        "id": str(uuid.uuid4()),
        "test": 1,
        "imp": [{
            "id": "1",
            "banner": {
                "w": 160,
                "h": 600,
                "pos": 3
            },
            "secure": 0
        }],
        "site": {
            "id": "1",
            "domain": config['rtb']['bid_site_domain'],
            "page": config['rtb']['bid_site_page'],
            "publisher": {
                "id": config['rtb']['bid_site_publisher_id']
            }
        },
        "device": {
            "dnt": 0,
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36",
            "ip": config['public_ip'],
            "geo": {
                "lat": config['geoip']['latitude'],
                "lon": config['geoip']['longitude'],
                "country": config['geoip']['country_code'],
                "region": config['geoip']['region_code'],
                "city": config['geoip']['city'],
                "zip": config['geoip']['zip_code'],
                "type": 2
            },
            "language": "en",
            "os": "OS X",
            "devicetype": 2,
            "osv": "10.12.6"
        },
        "user": {
            "id": config['rtb']['bid_user_id']
        },
        "at": 2
    })


def http_get_latency(host):
    """
    Performs http get request and returns latency.

    :param host: Hostname as string.
    :return: Timestamp as float of seconds or nothing
    """
    logger.debug('Sending HTTP GET to: ' + extract_hostname(host))
    try:
        s = requests.Session()
        s.mount('http://', requests.adapters.HTTPAdapter(max_retries=1))
        s.mount('https://', requests.adapters.HTTPAdapter(max_retries=1))
        start = time.time()
        req = s.get(host, timeout=config['timeout'])
        end = time.time()
        if req.status_code == 204 or req.status_code == requests.codes.ok:
            return end - start
        else:
            logger.error('Request failed to: ' + host + ' code=' + str(req.status_code) + ' text=' + str(req.text))
    except Exception as ex:
        logger.exception('Request failed to: ' + host)


def rtb_latency(host):
    """
    Sends test RTB bid to host and returns latency.

    :param host: Hostname as string
    :return: Timestamp as float of seconds or nothing
    """
    logger.debug('Sending test bid to: ' + extract_hostname(host))
    try:
        s = requests.Session()
        s.mount('http://', requests.adapters.HTTPAdapter(max_retries=1))
        s.mount('https://', requests.adapters.HTTPAdapter(max_retries=1))
        start = time.time()
        req = s.post(
            host,
            data=genbid(),
            timeout=config['timeout'],
            headers=config['rtb']['headers']
        )
        end = time.time()
        if req.status_code == 204 or req.status_code == requests.codes.ok:
            return end - start
        else:
            logger.error('Request failed to: ' + host + ' code=' + str(req.status_code) + ' text=' + str(req.text))
    except Exception as ex:
        logger.exception('Request failed to: ' + host)


def icmp_latency(host):
    """
    Pings a host. Requires script to be run as root in order to function.

    :param host: Hostname as string
    :return: Timestamp as float of seconds or nothing
    """
    logger.debug('Pinging host: ' + host)
    try:
        return ping.do_one(host, config['timeout'])
    except Exception as ex:
        logger.exception('Ping failed to: ' + host)


def average_latency(host, protocol):
    """
    Return average latency of checks to host for given protocol.
    Errors will break the loop and an average will be calculated of whatever data we have.
    If that doesn't work, it will return '-1'.

    :param host: hostname string
    :param protocol: protocol string
    :return: average latency in seconds as float
    """
    latencies = []
    for count in range(0, config['check_count']):
        if protocol == "icmp":
            result = icmp_latency(extract_hostname(host))
            if result:
                latencies.append(result)
            else:
                break
        elif protocol == "rtb":
            result = rtb_latency(host)
            if result:
                latencies.append(result)
            else:
                break
        elif protocol == "get":
            result = http_get_latency(host)
            if result:
                latencies.append(result)
            else:
                break
        else:
            logger.error('Unknown protocol: ' + protocol)
            return
    try:
        avg_latency = sum(latencies) / float(len(latencies))
    except:
        avg_latency = float('-1')
    return avg_latency


def send_graphite(
            provider,
            protocol,
            latency,
            remote_region,
            graphite_host=config["graphite_host"],
            graphite_port=config["graphite_port"],
            graphite_prefix=config["graphite_prefix"]
        ):
    """
    Send a latency metric to Graphite.

    Line format:
      prefix.provider.remote_region.local_host.protocol latency_in_milliseconds timestamp

    :param provider: provider name as string
    :param protocol: protocol as string
    :param latency: latency in seconds as float
    :param remote_region: geographic region of remote system as string
    :param graphite_host: graphite hostname as string
    :param graphite_port: graphite port as int
    :param graphite_prefix: graphite prefix as string
    :return: Nope
    """
    try:
        if latency == float('-1'):
            # Keep '-1' error values
            clean_latency = str(latency)
        else:
            # Convert float of seconds to int of milliseconds
            clean_latency = str(int(latency * 1000))
        # Construct line
        graphite_line = ' '.join([
            '.'.join([
                graphite_safe(graphite_prefix),
                graphite_safe(provider),
                graphite_safe(remote_region),
                graphite_safe(socket.getfqdn()),
                graphite_safe(protocol)
            ]),
            clean_latency,
            str(int(time.time()))
        ])
        logger.debug('Graphite line: ' + graphite_line)
        # Send line
        graphite_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        graphite_connection.connect((graphite_host, graphite_port))
        graphite_connection.sendall(graphite_line)
    except Exception as ex:
        logger.exception('Graphite exception')


def main_loop(host_dict):
    """
    This function loops through a dictionary of hosts and runs the other functions against them.

    :param host_dict:
    :return: Nope
    """
    logger.info('Starting latency check for all hosts.')
    for provider in host_dict:
        logger.info('Checking provider: ' + provider)
        for region in host_dict[provider]:
            for protocol in config['check_types']:
                latency = average_latency(
                    host=host_dict[provider][region],
                    protocol=protocol
                )
                send_graphite(
                    provider=provider,
                    protocol=protocol,
                    remote_region=region,
                    latency=latency
                )
    logger.info('Finished latency check.')


main_loop(build_host_dict())
