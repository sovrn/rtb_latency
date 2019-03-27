#!/usr/bin/python2

import ipwhois
import itertools
import json
import logging
import os
import pymysql
import re
import requests
import socket
import subprocess
import sys
import threading
import time
import urllib2
import uuid
import Queue
from multiprocessing import Pool
from multiprocessing.dummy import Pool as ThreadPool

logging.basicConfig(format='rtb_latency %(funcName)s %(levelname)s %(message)s')
logger = logging.getLogger(__file__)


def genconfig():
    """
    Reads config from file and further populates config with dynamic data.

    :return: config as dict
    """
    # Open config file
    logger.debug('Loading config file...')
    try:
        with open('config.json', 'r') as config_file:
            config = json.loads(config_file.read())
    except Exception:
        logger.exception('Trouble opening config file.')
        sys.exit(1)
    # Get public IP
    logger.debug('Requesting public IP from ipify.org...')
    try:
        pubiprequest = urllib2.urlopen(url='https://api.ipify.org')
        config['public_ip'] = pubiprequest.read()
        pubiprequest.close()
    except Exception:
        logger.exception('Error getting public IP from ipify.org.')
#    # Get GeoIP info
#    logger.debug('Requesting GeoIP from freegeoip.net...')
#    try:
#        geoiprequest = urllib2.urlopen(url='http://freegeoip.net/json/' + config['public_ip'])
#        config['geoip'] = json.loads(geoiprequest.read())
#        geoiprequest.close()
#    except Exception:
#        logger.exception('Error getting GeoIP from freegeoip.net.')
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


def extract_path(string):
    """
    Extract FQDN or IP from a full URL

    :param string: A URL as a string
    :return: FQDN or IP as a string
    """
    return re.sub(r'[^/]*//[^:/]*', '', string)


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
    # Collapse repeating underscores into one
    while '__' in string:
        string = string.replace('__', '_')
    return string


def build_host_dict():
    """
    Generates host list from sources defined in config file.
    Example output:
        {
            "provider_name": {
                "path": "URI suffix",
                "region_major": {
                    "region_minor": ["IP_address", ...],
                    "star": ["IP_address", ...]
                },
            },
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
            except Exception:
                logger.exception('Could not open JSON host file: ' + filepath)
        elif config['load_hosts'][id]['method'] == 'mysql':
            try:
                logger.debug('Loading hosts from MySQL DB...')
                mysql_conn = pymysql.cursors.DictCursor(pymysql.connect(
                    host=config['load_hosts'][id]['mysql_host'],
                    user=config['load_hosts'][id]['mysql_user'],
                    passwd=config['load_hosts'][id]['mysql_pass'],
                    database=config['load_hosts'][id]['mysql_db']
                ))
                result_count = mysql_conn.execute(
                    config['load_hosts'][id]['mysql_query']
                )
                result_count
                result_dict = mysql_conn.fetchall()
                for id, row in enumerate(result_dict):
                    row
                    provider = result_dict[id]['provider']
                    if provider not in checks:
                        checks[provider] = {}
                        for region_major in config['regions']['major']:
                            checks[provider][region_major] = {'star': []}
                            for region_minor in config['regions']['minor']:
                                checks[provider][region_major][region_minor] = []
                    for region in result_dict[id]:
                        if 'http' in result_dict[id][region]:
                            try:
                                region_major, region_minor = region.split('_')
                                provider_host = extract_hostname(result_dict[id][region])
                                checks[provider]['path'] = extract_path(result_dict[id][region])
                                _, _, provider_endpoints = socket.gethostbyname_ex(provider_host)
                                provider_endpoints.append(provider_host)
                                for endpoint in provider_endpoints:
                                    if endpoint not in checks[provider][region_major][region_minor]:
                                        checks[provider][region_major][region_minor].append(endpoint)
                                    if endpoint not in checks[provider][region_major]['star']:
                                        checks[provider][region_major]['star'].append(endpoint)
                            except Exception:
                                logger.exception('Trouble processing provider ' + provider + ' URL: ' + result_dict[id][region])
            except Exception:
                logger.exception('Could not load hosts from MySQL.')
        else:
            logger.error('Unknown source type for hosts: ' + source)
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
                "zip": str(config['geoip']['zip_code']),
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


def net_debug(ip, host):
    """
    Gather path information about a remote IP for debugging

    :param ip: IP address to check path to.
    :return: JSON dictionary
    """
    try:
        try:
            as_remote = ipwhois.asn.IPASN(ipwhois.net.Net(ip)).lookup()
            as_local = ipwhois.asn.IPASN(ipwhois.net.Net(config['public_ip'])).lookup()
        except Exception:
            as_local = {
                'asn': None,
                'asn_cidr': None,
            }
            as_remote = {
                'asn': None,
                'asn_cidr': None,
                'asn_description': None,
            }
            logger.exception('Unable to determine ASN for IP: ' + ip)
        try:
            traceroute = subprocess.check_output([
                'traceroute', '-A', '-I', '-e', '-N 1', '-q 1', ip
            ]).split('\n')
            del traceroute[0]
            del traceroute[-1]
        except Exception:
            logger.exception('Traceroute failed for ' + ip)
            traceroute = []
        results = json.dumps({
            'local_asn': as_local['asn'],
            'local_asn_cidr': as_local['asn_cidr'],
            'local_ip': config['public_ip'],
            'remote_asn': as_remote['asn'],
            'remote_asn_cidr': as_remote['asn_cidr'],
            'remote_asn_descr': as_remote['asn_description'],
            'remote_hostname': host,
            'remote_ip': ip,
            'traceroute': traceroute
        })
        return results
    except Exception:
        logger.exception('Could not retrieve net debugging info for ' + ip)
        return {}


def http_get_latency(host):
    """
    Performs an HTTP GET request and returns latency.

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
        if req.status_code <= 204 or req.status_code >= 200:
            return end - start
        else:
            logger.error('Request failed to: ' + host + ' code=' + str(req.status_code) + ' text=' + str(req.text))
    except Exception:
        logger.exception('Request failed to: ' + host)


def rtb_latency(host):
    """
    Sends a test RTB bid to host and returns latency.

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
        if req.status_code <= 204 or req.status_code >= 200:
	    delta = float (end - start)
            return delta 
        else:
            logger.error('Request failed to: ' + host + ' code=' + str(req.status_code) + ' text=' + str(req.text))
    except Exception:
        logger.exception('Request failed to: ' + host)


def ping(server='example.com', count=1, wait_sec=1):
    """
    :rtype: dict or None
    """
    cmd = "ping -c {} -W {} {}".format(count, wait_sec, server).split(' ')
    try:
        output = subprocess.check_output(cmd).decode().strip()
        lines = output.split("\n")
        loss = float (lines[-2].split(',')[2].split()[0].split('%')[0])
        timing = lines[-1].split()[3].split('/')
        min = float (timing[0])
        avg = float (timing[1])
        max = float (timing[2])
        mdev = float (timing[3])
        return [min, avg, max, mdev, loss]

    except Exception as e:
        print(e)
        return None


def icmp_latency(host):
    """
    Pings a host. Requires script to be run as root in order to function.

    :param host: Hostname as string
    :return: Timestamp as float of seconds or nothing
    """
    try:
	r = ping(server=host, count=1, wait_sec=1)

        logger.debug('Pinging host: ' + host + ' [Min/Avg/Max/Loss] or None: ' + str(r))

	if r is None :
	  return float(-1)

	else:
	  result = float(r[1]) / 1000
          return result

    except Exception:
        logger.exception('Ping failed to: ' + host)


def average_latency(host, protocol, path):
    """
    Return average latency of checks to host for given protocol.
    Errors will break the loop and an average will be calculated of whatever data we have.
    If that doesn't work, it will return '-1'.

    :param host: hostname string
    :param protocol: protocol string
    :return: average latency in seconds as float
    """
    ip = socket.gethostbyname(extract_hostname(host))
    latencies = []
    for count in range(0, config['check_count']):
        if protocol == "icmp":
            result = icmp_latency(ip)
            if result != float(-1):
                latencies.append(result)
            else:
                break
        elif protocol == "rtb":
            if re.match("[A-Za-z]", host) is not None:
                result = rtb_latency('http://' + host + path)
                if result != float(-1):
                    latencies.append(result)
                else:
                    break
        elif protocol == "get":
            result = http_get_latency('http://' + ip + path)
            if result:
                latencies.append(result)
            else:
                break
        else:
            logger.error(str(count) + ' Unknown protocol: ' + protocol)
            return
    try:
        avg_latency = sum(latencies) / float(len(latencies))
    except:
        avg_latency = -1

    if avg_latency > config['latency_warn']:
        logger.warn('latency=' + str(avg_latency) + 's ' + net_debug(ip, host))
    return avg_latency


def send_graphite(
            provider,
            protocol,
            latency,
            endpoint,
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
            clean_latency = str(round(latency * 1000, 2))
        # Construct line
        graphite_line = ' '.join([
            '.'.join([
                graphite_safe(graphite_prefix),
                graphite_safe(provider),
                graphite_safe(remote_region),
                graphite_safe(endpoint),
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
    except Exception:
        logger.exception('Graphite exception')


def check_and_send(opt_dict):
    """
    Get average latency and ship it to Graphite. This is needed for multithreading.

    :param opt_dict: dictionary containing the keys and values that are requested below:
    :returns: nothing
    """
    latency = average_latency(
        host=opt_dict['endpoint'],
        path=opt_dict['path'],
        protocol=opt_dict['protocol']
    )
    if latency == float(-1) and opt_dict['protocol'] == "rtb":
        return

    send_graphite(
        endpoint=opt_dict['endpoint'],
        latency=latency,
        protocol=opt_dict['protocol'],
        provider=opt_dict['provider'],
        remote_region=opt_dict['region']
    )


def main_loop(host_dict):
    """
    This function loops through the dictionary of hosts, populates a list of actions,
    and kicks off that list in multiple threads.

    :param host_dict:
    :return: Nope
    """
    checklist = []
    logger.info('Starting latency check for all hosts.')
    for provider in host_dict:
        for region_major in config['region_filter']['major']:
            for region_minor in config['region_filter']['minor']:
                for endpoint in host_dict[provider][region_major][region_minor]:
                    for protocol in config['check_types']:
                        checklist.append({
                            'endpoint': endpoint,
                            'path': host_dict[provider]['path'],
                            'protocol': protocol,
                            'provider': provider,
                            'region': region_major + '_' + region_minor
                        })
    pool = ThreadPool(config['threads'])
    pool.map(check_and_send, checklist)
    pool.close()
    pool.join()
    logger.info('Finished latency check.')


main_loop(build_host_dict())
