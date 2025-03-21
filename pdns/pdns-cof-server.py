#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# A Passive DNS COF compliant passive DNS server for the analyzer-d4-passivedns
#
# The output format is compliant with Passive DNS - Common Output Format
#
# https://tools.ietf.org/html/draft-dulaunoy-dnsop-passive-dns-cof
#
# This software is part of the D4 project.
#
# The software is released under the GNU Affero General Public version 3.
#
# Copyright (c) 2013-2022 Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2019-2022 Computer Incident Response Center Luxembourg (CIRCL)


from datetime import date
import tornado.escape
import tornado.ioloop
import tornado.web

import iptools
import redis
import json
import os

analyzer_redis_host = os.getenv('D4_ANALYZER_REDIS_HOST', '127.0.0.1')
analyzer_redis_port = int(os.getenv('D4_ANALYZER_REDIS_PORT', 6400))

r = redis.StrictRedis(host=analyzer_redis_host, port=analyzer_redis_port, db=0)

rrset_supported = ['1', '2', '5', '15', '16', '28', '33', '46']
expiring_type = ['16']


origin = "origin not configured"


def getFirstSeen(t1=None, t2=None):
    if t1 is None or t2 is None:
        return False
    rec = f's:{t1.lower()}:{t2.lower()}'
    for rr in rrset:
        if (rr['Value']) is not None and rr['Value'] in rrset_supported:
            qrec = f'{rec}:{rr["Value"]}'
            recget = r.get(qrec)
            if recget is not None:
                return int(recget.decode(encoding='UTF-8'))


def getLastSeen(t1=None, t2=None):
    if t1 is None or t2 is None:
        return False
    rec = f'l:{t1.lower()}:{t2.lower()}'
    for rr in rrset:
        if (rr['Value']) is not None and rr['Value'] in rrset_supported:
            qrec = f'{rec}:{rr["Value"]}'
            recget = r.get(qrec)
            if recget is not None:
                return int(recget.decode(encoding='UTF-8'))


def getCount(t1=None, t2=None):
    if t1 is None or t2 is None:
        return False
    rec = f'o:{t1.lower()}:{t2.lower()}'
    for rr in rrset:
        if (rr['Value']) is not None and rr['Value'] in rrset_supported:
            qrec = f'{rec}:{rr["Value"]}'
            recget = r.get(qrec)
            if recget is not None:
                return int(recget.decode(encoding='UTF-8'))


def getRecord(t=None):
    if t is None:
        return False
    rrfound = []
    for rr in rrset:
        if (rr['Value']) is not None and rr['Value'] in rrset_supported:
            rec = f'r:{t}:{rr["Value"]}'
            setsize = r.scard(rec)
            if setsize < 200:
                rs = r.smembers(rec)
            else:
                # TODO: improve with a new API end-point with SSCAN
                # rs = r.srandmember(rec, number=300)
                rs = False

            if rs:
                for v in rs:
                    rrval = {}
                    rdata = v.decode(encoding='UTF-8').strip()
                    rrval['time_first'] = getFirstSeen(t1=t, t2=rdata)
                    rrval['time_last'] = getLastSeen(t1=t, t2=rdata)
                    if rrval['time_first'] is None:
                        break
                    rrval['count'] = getCount(t1=t, t2=rdata)
                    rrval['rrtype'] = rr['Type']
                    rrval['rrname'] = t
                    rrval['rdata'] = rdata
                    if origin:
                        rrval['origin'] = origin
                    rrfound.append(rrval)
    return rrfound


def getAssociatedRecords(rdata=None):
    if rdata is None:
        return False
    rec = f'v:{rdata.lower()}'
    records = []
    for rr in rrset:
        if (rr['Value']) is not None and rr['Value'] in rrset_supported:
            qrec = f'{rec}:{rr["Value"]}'
            if r.smembers(qrec):
                for v in r.smembers(qrec):
                    records.append(v.decode(encoding='UTF-8'))
    return records


def RemDuplicate(d=None):
    if d is None:
        return False
    outd = [dict(t) for t in set([tuple(o.items()) for o in d])]
    return outd


def JsonQOF(rrfound=None, RemoveDuplicate=True):
    if rrfound is None:
        return False
    rrqof = ""

    if RemoveDuplicate:
        rrfound = RemDuplicate(d=rrfound)

    for rr in rrfound:
        rrqof = rrqof + json.dumps(rr) + "\n"
    return rrqof


class InfoHandler(tornado.web.RequestHandler):
    def get(self):
        stats = int(r.get("stats:processed"))
        response = {'version': 'git', 'software': 'analyzer-d4-passivedns'}
        response['stats'] = stats
        sensors = r.zrevrange('stats:sensors', 0, -1, withscores=True)
        rsensors = []
        for x in sensors:
            d = dict()
            d['sensor_id'] = x[0].decode()
            d['count'] = int(float(x[1]))
            rsensors.append(d)
        response['sensors'] = rsensors
        self.write(response)


class QueryHandler(tornado.web.RequestHandler):
    def get(self, q):
        print(f'query: {q}')
        if iptools.ipv4.validate_ip(q) or iptools.ipv6.validate_ip(q):
            for x in getAssociatedRecords(q):
                self.write(JsonQOF(getRecord(x)))
        else:
            self.write(JsonQOF(getRecord(t=q.strip())))


class FullQueryHandler(tornado.web.RequestHandler):
    def get(self, q):
        print(f'fquery: {q}')
        if iptools.ipv4.validate_ip(q) or iptools.ipv6.validate_ip(q):
            for x in getAssociatedRecords(q):
                self.write(JsonQOF(getRecord(x)))
        else:
            for x in getAssociatedRecords(q):
                self.write(JsonQOF(getRecord(t=x.strip())))


application = tornado.web.Application(
    [
        (r"/query/(.*)", QueryHandler),
        (r"/fquery/(.*)", FullQueryHandler),
        (r"/info", InfoHandler),
    ]
)

if __name__ == "test":

    qq = ["foo.be", "8.8.8.8"]

    for q in qq:
        if iptools.ipv4.validate_ip(q) or iptools.ipv6.validate_ip(q):
            for x in getAssociatedRecords(q):
                print(JsonQOF(getRecord(x)))
        else:
            print(JsonQOF(getRecord(t=q)))
else:
    application.listen(8400)
    tornado.ioloop.IOLoop.instance().start()
