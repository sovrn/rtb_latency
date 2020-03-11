#!/usr/bin/env python3

"""
rtb_single - send a single RTB request to one or more URIs

Usage: rtb_single.py [URI, ...]
"""


import json
import requests
import sys
import time
import uuid


config = {
    "timeout": 1,
    "headers": {
        "Content-Type": "application/json",
        "x-openrtb-version": "2.3"
    }
}


def genbid():
    return json.dumps({
        "ext": {
            "pchain": "pchain"
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
            "domain": "example.com",
            "page": "http://test.example.com/latency/monitor/test",
            "publisher": {
                "id": "1"
            }
        },
        "device": {
            "dnt": 0,
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36",
            "ip": "8.8.8.8",
            "geo": {
                "lat": 37.4060,
                "lon": -122.0785,
                "country": "USA",
                "region": "CA",
                "city": "Mountain View",
                "zip": "94043",
                "type": 2
            },
            "language": "en",
            "os": "OS X",
            "devicetype": 2,
            "osv": "10.12.6"
        },
        "user": {
            "id": "test_user"
        },
        "at": 2
    })


def rtb_latency(uri):
    print('Sending RTB test bid to: %s', uri)
    try:
        s = requests.Session()
        start = time.time()
        req = s.post(
            uri,
            data=genbid(),
            timeout=config['timeout'],
            headers=config['headers'])
        end = time.time()
        print('Request time was %s for host: %s', uri, end - start)
        if req.status_code >= 204 and req.status_code <= 200:
            print(
                'Request failed to: %s\n\ncode:\n%s\n\ntext:\n%s',
                uri, req.status_code, req.text)
    except Exception as e:
            print('Request failed to: %s\n%s', uri, e)


print('Starting RTB latency check.')
for uri in sys.argv[1:]:
    rtb_latency(uri)
print('Finished RTB latency check.')

