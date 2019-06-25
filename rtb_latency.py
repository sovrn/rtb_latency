#!/usr/bin/env python3

import concurrent.futures
import itertools
import certifi
import ipwhois
import itertools
import json
import logging
import netaddr
import os
import pymysql
import re
import requests
import socket
import subprocess
import sys
import threading
import time
import urllib3
import uuid

# Enforce Python version
if sys.version_info[0] < 3 and sys.version_info[1] < 5:
  print('ERROR: This script requires Python 3.5 or greater, exiting.')
  sys.exit(1)

logging.basicConfig(format='%(funcName)s %(levelname)s %(message)s')
log = logging.getLogger(__file__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def dj(_dict):
  """Converts dicts to JSON and safely handles non-serializable items"""
  return json.dumps(
    _dict,
    default=lambda o: 'ERROR: Item not JSON serializable',
    sort_keys=True,
    indent=3)


class Config:
  """Configuration Object"""
  config = {}
  def __init__(self):
    import argparse
    parser = argparse.ArgumentParser(description="""
                        This script checks network and RTB latency to remote hosts.""")
    parser.add_argument('--checkhost',
                        help='Check single host instead of full suite of checks.')
    parser.add_argument('--protocol', default='RTB',
                        help='Specify RTB, HTTP, or RTB for a single host check.')
    parser.add_argument('--timeout', default=0.5, type=float,
                        help='Specify timeout for a single host check as a float of seconds. Default=0.5')
    parser.add_argument('--path', default='/',
                        help='Path for HTTP and RTB checks. Default=./config.json')
    parser.add_argument('--configfile', default='config.json',
                        help='File to read provider configuration from. Default=./config.json')
    args = vars(parser.parse_args())
    # Try loading config from file
    try:
      with open(args['configfile'], 'r') as configfile:
        jsonconf = json.loads(configfile.read())
    except Exception as trace:
      log.exception('Error opening config file.')
      log.debug(trace, exc_info=True)
      sys.exit(1)
    log.debug('Requesting GeoIP from geoiplookup.io...')
    try:
      request = requests.get('https://json.geoiplookup.io/')
      self.config['geoip'] = request.json()
      self.config['public_ip'] = self.config['geoip']['ip']
    except Exception as e:
      log.error('Error obtaining GeoIP from geoiplookup.io:\n%s', e)
    # Merge config file with command-line arguments
    self.config = {**jsonconf, **args}
    # Set log level from resulting config
    log.setLevel(logging.getLevelName(self.config['log_level'].upper()))
  def __str__(self):
    """Returns a JSON string of self.__dict__"""
    return dj(self.__dict__)
  def rconf(self):
    """Returns a JSON string of self.config"""
    return self.config


config = Config().rconf()


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
                log.debug('Loading hosts from JSON file: ' + filepath)
                checks.update(json.loads(open(filepath, 'r').read()))
            except Exception:
                log.exception('Could not open JSON host file: ' + filepath)
        elif config['load_hosts'][id]['method'] == 'mysql':
            try:
                log.debug('Loading hosts from MySQL DB...')
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
                                log.exception('Trouble processing provider ' + provider + ' URL: ' + result_dict[id][region])
            except Exception:
                log.exception('Could not load hosts from MySQL.')
        else:
            log.error('Unknown source type for hosts: ' + source)
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


def net_debug(host):
    """
    Gather path information about a remote IP for debugging

    :param ip: IP address to check path to.
    :return: JSON dictionary
    """
    if netaddr.valid_ipv4(host):
        ip = host
        try:
            hostname = socket.gethostbyaddr(host)[0]
        except:
            hostname = host
    else:
        ip = socket.gethostbyname(host)
        hostname = host
    try:
        as_remote = ipwhois.asn.IPASN(ipwhois.net.Net(ip)).lookup()
        as_local = ipwhois.asn.IPASN(ipwhois.net.Net(config['public_ip'])).lookup()
    except Exception as e:
        as_local = {
            'asn': None,
            'asn_cidr': None,
        }
        as_remote = {
            'asn': None,
            'asn_cidr': None,
            'asn_description': None,
        }
        log.error('Unable to determine ASN for IP: %s\n%s', ip, e)
    try:
        command = ['traceroute', '-A', '-I', '-e', '-N 1', '-q 1', str(ip)]
        cmd = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True)
        output = cmd.communicate()
        retcode = cmd.poll()
        if retcode == 0:
            traceroute = output[0].split('\n')
            del traceroute[0]
            del traceroute[-1]
        else:
            raise subprocess.CalledProcessError(retcode, command, output=output)
    except Exception as e:
        log.error('Traceroute failed for %s:\n%s', ip, e)
        log.debug('command: %s\nstdout:\n%s\nstderr:\n%s', command, output[0], output[1])
        traceroute = []
    log.warn('for host: %s\n%s', host, dj({
        'local_asn': as_local['asn'],
        'local_asn_cidr': as_local['asn_cidr'],
        'local_ip': config['public_ip'],
        'remote_asn': as_remote['asn'],
        'remote_asn_cidr': as_remote['asn_cidr'],
        'remote_asn_descr': as_remote['asn_description'],
        'remote_hostname': hostname,
        'remote_ip': ip,
        'traceroute': traceroute
    }))


def http_get_latency(host, path):
    """
    Performs an HTTP GET request and returns latency.

    :param host: Hostname as string.
    :return: Timestamp as float of seconds or nothing
    """
    log.debug('Sending HTTP GET to: ' + extract_hostname(host))
    for proto in ['https://', 'http://']:
        try:
            s = requests.Session()
            s.mount(proto, requests.adapters.HTTPAdapter(max_retries=1))
            start = time.time()
            req = s.get(
                proto + host + path,
                timeout=config['timeout'])
            end = time.time()
            if req.status_code < 400:
                return end - start
            else:
                log.error('Request failed to: %s code=%s text=%s', host, req.status_code, req.text)
        except Exception as e:
            log.error('Request failed to: %s\n%s', host, e)


def rtb_latency(host, path):
    """
    Sends a test RTB bid to host and returns latency.

    :param host: Hostname as string
    :return: Timestamp as float of seconds or nothing
    """
    log.debug('Sending test bid to: %s', host)
    for proto in ['https://', 'http://']:
        try:
            s = requests.Session()
            s.mount(proto, requests.adapters.HTTPAdapter(max_retries=1))
            start = time.time()
            req = s.post(
                proto + host + path,
                data=genbid(),
                timeout=config['timeout'],
                headers=config['rtb']['headers'],
                verify=False)
            end = time.time()
            log.debug('Request time for host %s: %s', host, end - start)
            if req.status_code <= 204 and req.status_code >= 200:
                return end - start
            else:
                log.error('Request failed to: %s code=%s text=%s', host, req.status_code, req.text)
        except Exception as e:
            log.error('Request failed to: %s\n%s', host)
            log.debug(e, exc_info=True)


def ping(host='google.com', number=1, wait_sec=1):
    """
    Ping host and format output

    :param host: hostname or IP as string
    :param number: ping count
    :param wait_sec: ping timeout
    :return: dict
    """
    log.debug('Pinging host: %s', host)
    result = {
        'host': host,
        'count': number
    }
    try:
        command = ['ping', '-c', str(number), '-W', str(wait_sec), str(host)]
        cmd = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True)
        output = cmd.communicate()
    except Exception as e:
        log.warn('Error calling ping:\n%s', e)
        log.debug('command: %s\nstdout:\n%s\nstderr:\n%s', command, output[0], output[1])
    try:
        for line in output[0].split('\n'):
            if 'round-trip' in line:
                timing = line.split()[3].split('/')
                result['avg'] = float(timing[1]) / 1000
                result['dev'] = float(timing[3]) / 1000
                result['max'] = float(timing[2]) / 1000
                result['min'] = float(timing[0]) / 1000
            if 'packets' in line:
                result['loss'] = line.split()[5]
        log.debug('Ping result for host %s:\n%s', host, dj(result))
    except Exception as e:
        log.error('Unable to parse output of ping: %s', e)
    return result


def icmp_latency(host):
    """
    Pings a host. Requires script to be run as root in order to function.

    :param host: Hostname as string
    :return: Timestamp as float of seconds or nothing
    """
    try:
        result = ping(host=host, number=1, wait_sec=1)
        return result['avg']
    except:
        pass


def average_latency(host, protocol, path='/'):
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
            result = icmp_latency(host)
            if result:
                latencies.append(result)
            else:
                break
        elif protocol == "rtb":
            result = rtb_latency(host, path)
            if result:
                latencies.append(result)
            else:
                break
        elif protocol == "http":
            result = http_get_latency(host, path)
            if result:
                latencies.append(result)
            else:
                break
        else:
            log.error('Unknown protocol: %s (count=%s)', protocol, count)
            return
    try:
        avg_latency = sum(latencies) / float(len(latencies))
    except Exception as e:
        log.debug(e)
        avg_latency = -1
    if avg_latency > config['latency_warn'] or avg_latency == -1:
        log.warn('Latency to %s is %ss.', host, str(avg_latency))
        net_debug(host)
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
            clean_latency = str(int(latency * 1000))
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
        log.debug('Graphite line: ' + graphite_line)
        # Send line
        graphite_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        graphite_connection.connect((graphite_host, graphite_port))
        graphite_connection.sendall(graphite_line)
    except Exception as e:
        log.error(e)


def check_and_send(opt_dict):
    """
    Get average latency and ship it to Graphite. This is needed for multithreading.

    :param opt_dict: dictionary containing the keys and values that are requested below:
    :returns: nothing
    """
    if opt_dict['protocol'] == 'rtb' and netaddr.valid_ipv4(opt_dict['endpoint']):
        log.debug('Skipping RTB check for naked IP %s', opt_dict['endpoint'])
        return opt_dict
    latency = average_latency(
        host=opt_dict['endpoint'],
        path=opt_dict['path'],
        protocol=opt_dict['protocol'])
    # send_graphite(
    #     endpoint=opt_dict['endpoint'],
    #     latency=latency,
    #     protocol=opt_dict['protocol'],
    #     provider=opt_dict['provider'],
    #     remote_region=opt_dict['region'])
    return opt_dict


def send_report():
  pass


def main_loop(host_dict):
  """
  This function loops through the dictionary of hosts, populates a list of actions,
  and kicks off that list in multiple threads.

  :param host_dict:
  :return: Nope
  """
  checklist = []
  log.info('Starting RTB latency check.')
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
              'region': region_major + '_' + region_minor})
  with concurrent.futures.ThreadPoolExecutor(max_workers=config['threads']) as executor:
    # Create dynamic dictionary with all pull operations that the workers can consume
    checks = {executor.submit(check_and_send, check): check for check in checklist}
    # Run the dictionary and iterate over the results
    for check in concurrent.futures.as_completed(checks):
      try:
        # Merge the results into master dictionary
        # hosts = {**hosts, **provider.result()}
        log.debug('Check completed:\n%s', dj(check))
      except Exception as trace:
        log.exception('Error executing subthread:\n%s', trace)
  log.info('Finished RTB latency check.')


if __name__ == '__main__':
  if config['checkhost']:
    avg_latency = average_latency(config['checkhost'].lower(), config['protocol'], config['path'])
    if avg_latency:
      if avg_latency > config['timeout'] or avg_latency == -1:
        sys.exit(1)
    else:
      sys.exit(1)
  else:
    main_loop(build_host_dict())
