#!/usr/bin/env python

import urllib
import urllib2
import base64
import time
import datetime
import sys
import os
import re
import thread
import codecs
import argparse
import xml.etree.ElementTree as ET
from collections import namedtuple
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

# Acano API bug: request 'https://<server_ip>:<server_port>/api/v1/calls/$call_id/callLegs?limit=100&offset=0' return only 10 items

# TODO: drop off
SERVER = '<server_ip>:<server_port>'
USERNAME = 'api-login'
PASSWORD = 'api-password'

POOL_TIME_SEC = 5
MAX_LOSS = 3
MIN_BITRATE = 500000
MAX_DELTA_BITRATE = 300000
SUMMARY_FILENAME = 'summary.txt'

WEB_PORT_NUMBER = 8098


# BASE_DIR = 'c:\\CMS_recorder\\acano_logs'
# SLASH = '\\'

BASE_DIR = '/root/CMS_recorder/acano_logs'
SLASH = '/'


def get_http_data(url):
    try:
        request = urllib2.Request(url)
        base64string = base64.encodestring('%s:%s' % (USERNAME, PASSWORD)).replace('\n', '')
        request.add_header('Authorization', 'Basic %s' % base64string)
        result = urllib2.urlopen(request)

        res = result.read()

    except urllib2.HTTPError:
        res = None

    except urllib2.URLError:
        res = None

    return res


VInfo = namedtuple('VInfo', 'codec width height frame_rate bit_rate loss jitter rtt')
AInfo = namedtuple('AInfo', 'codec loss jitter bit_rate rtt')


class CallLegTimeInfo(object):
    def __init__(self, conf_type, dur_sec, state, xml_root):
        self.timestamp = datetime.datetime.now()
        self.conf_type = conf_type
        self.dur_sec = dur_sec
        self.state = state

        self.v_rx = self._parse_video(xml_root.findall('status/rxVideo'))
        self.v_tx = self._parse_video(xml_root.findall('status/txVideo'))

        self.a_rx = self._parse_audio(xml_root.findall('status/rxAudio'))
        self.a_tx = self._parse_audio(xml_root.findall('status/txAudio'))

        # print conf_type, '/', state, '/', dur_sec
        # print 'V-rx', self.v_rx
        # print 'V-tx', self.v_tx
        # print 'A-rx', self.a_rx
        # print 'A-tx', self.a_tx

    def _first_item_str(self, xml_list, func=None):
        res_str = xml_list[0].text if len(xml_list) == 1 else ''

        if func:
            return func(res_str) if res_str != '' else func('0')
        else:
            return res_str

    def _parse_video(self, xml_video):
        xml_video = xml_video[0] if len(xml_video) > 0 else None

        if xml_video is not None:
            return VInfo(
                self._first_item_str(xml_video.findall('codec')),
                self._first_item_str(xml_video.findall('width')),
                self._first_item_str(xml_video.findall('height')),
                self._first_item_str(xml_video.findall('frameRate')),
                self._first_item_str(xml_video.findall('bitRate'), func=int),
                self._first_item_str(xml_video.findall('packetLossPercentage'), func=float),
                self._first_item_str(xml_video.findall('jitter')),
                self._first_item_str(xml_video.findall('roundTripTime')))

        return None

    @staticmethod
    def _str_video_header():
        return '%-7s%-8s%-8s%-6s%-10s%-7s%-8s%-5s' % ('codec', 'width', 'height', 'fps', 'bitrate', 'loss', 'jitter', 'RTT')

    def _str_video_quality(self, v_qual):
        if v_qual:
            return '%-7s%-8s%-8s%-6s%-10s%-7s%-8s%-5s' % (v_qual.codec, v_qual.width, v_qual.height, v_qual.frame_rate, v_qual.bit_rate, v_qual.loss, v_qual.jitter, v_qual.rtt)
        else:
            return ' ' * 59

    def _parse_audio(self, xml_audio):
        xml_audio = xml_audio[0] if len(xml_audio) > 0 else None

        if xml_audio is not None:
            return AInfo(
                self._first_item_str(xml_audio.findall('codec')),
                self._first_item_str(xml_audio.findall('packetLossPercentage')),
                self._first_item_str(xml_audio.findall('jitter')),
                self._first_item_str(xml_audio.findall('bitRate')),
                self._first_item_str(xml_audio.findall('roundTripTime')))

        return None

    @staticmethod
    def _str_audio_header():
        return '%-6s %-5s %-7s %-8s %-5s' % ('codec', 'loss', 'jitter', 'bitrate', 'RTT')

    def _str_audio_quality(self, a_qual):
        if a_qual:
            return '%-6s %-5s %-7s %-8s %-5s' % (a_qual.codec, a_qual.loss, a_qual.jitter, a_qual.bit_rate, a_qual.rtt)
        else:
            return ' ' * 30

    @staticmethod
    def write_quality_header(wfile):
        # wfile.write('%30s %6s %20s \n' % ('time', 'dur.', 'state', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''))
        wfile.write('%s \n' % ('-' * 230))
        wfile.write('%s |  INCOMING VIDEO %s |  OUTGOING VIDEO %s |  INCOMING AUDIO %s |  OUTGOING AUDIO \n' % (' ' * 38, ' ' * 41, ' ' * 41, ' ' * 18))
        wfile.write('%s \n' % ('-' * 230))
        wfile.write('%-20s %-6s %-11s %s %s %s %s\n' % (
            'time',
            'dur.',
            'state',
            CallLegTimeInfo._str_video_header(),
            CallLegTimeInfo._str_video_header(),
            CallLegTimeInfo._str_audio_header(),
            CallLegTimeInfo._str_audio_header(),
        ))

    @staticmethod
    def write_quality_footer(wfile):
        wfile.write('\n' * 1)

    def write_to_file(self, wfile):
        wfile.write('%-20s %-6s %-11s %s %s %s %s\n' % (
            self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            self.dur_sec, self.state,
            self._str_video_quality(self.v_rx),
            self._str_video_quality(self.v_tx),
            self._str_audio_quality(self.a_rx),
            self._str_audio_quality(self.a_tx)
        ))


class QualityError:
    No = 0
    PacketLoss = 1 << 0
    LowBitrate = 1 << 1
    ScatterBitrate = 1 << 2

    @staticmethod
    def str(attrs):
        return reduce(
            lambda x, y: x + (' ' if x != '' and y != '' else '') + y,
            map((lambda attr: quality_error_flags[attr] if (attr & attrs) == attr else ''), quality_error_flags.keys()))


quality_error_flags = {
    QualityError.No: '',
    QualityError.PacketLoss: 'PKT-LOSS',
    QualityError.LowBitrate: 'LOW-BITRATE',
    QualityError.ScatterBitrate: 'SCATTER-BITRATE'
}


class VideoExt(object):
    def __init__(self, max_loss, min_br, max_br):
        self.max_loss = max_loss
        self.min_br = min_br
        self.max_br = max_br

    def update_extremes(self, v_qual):
        errors = QualityError.No

        if v_qual.loss > self.max_loss:
            self.max_loss = v_qual.loss

        if v_qual.bit_rate < self.min_br:
            self.min_br = v_qual.bit_rate

        if v_qual.bit_rate > self.max_br:
            self.max_br = v_qual.bit_rate

        if self.max_loss > MAX_LOSS:
            errors |= QualityError.PacketLoss

        if self.min_br < MIN_BITRATE:
            errors |= QualityError.LowBitrate

        if (self.max_br - self.min_br) > MAX_DELTA_BITRATE:
            errors |= QualityError.ScatterBitrate

        return errors


class CallLeg(object):
    def __init__(self, leg_id, leg_name, remote_party):
        self.leg_id = leg_id
        self.leg_name = leg_name
        self.remote_party = remote_party
        self._quality = []

        self.ex_v_rx = None
        self.ex_v_tx = None
        self._qual_errors = QualityError.No

    def _update_video_extremes(self, v_qual, is_recv):
        errors = QualityError.No

        if v_qual:
            if is_recv:
                if self.ex_v_rx:
                    errors = self.ex_v_rx.update_extremes(v_qual)
                else:
                    self.ex_v_rx = VideoExt(v_qual.loss, v_qual.bit_rate, v_qual.bit_rate)
            else:
                if self.ex_v_tx:
                    errors = self.ex_v_tx.update_extremes(v_qual)
                else:
                    self.ex_v_tx = VideoExt(v_qual.loss, v_qual.bit_rate, v_qual.bit_rate)

        return errors

    def update_leg(self):
        str_call_leg = get_http_data('https://' + SERVER + '/api/v1/callLegs/' + self.leg_id)

        if str_call_leg:
            xml_call_leg = ET.fromstring(str_call_leg)

            xml_type = xml_call_leg.findall('type')
            str_type = xml_type[0].text if len(xml_type) == 1 else '<unknown>'

            xml_status = xml_call_leg.findall('status/state')
            str_status = xml_status[0].text if len(xml_status) == 1 else '<unknown>'

            xml_dur = xml_call_leg.findall('status/durationSeconds')
            str_dur = xml_dur[0].text if len(xml_dur) == 1 else '<unk>'

            call_leg_info = CallLegTimeInfo(str_type, str_dur, str_status, xml_call_leg)

            self._quality.append(call_leg_info)

            self._qual_errors |= self._update_video_extremes(call_leg_info.v_rx, True)
            self._qual_errors |= self._update_video_extremes(call_leg_info.v_tx, False)

            if self._qual_errors != QualityError.No:
                print '*** %s' % (QualityError.str(self._qual_errors))

        return True if str_call_leg is not None else False

    def is_critical_quality(self):
        return self._qual_errors != QualityError.No

    def get_quality_errors(self):
        return self._qual_errors

    def complete_leg(self, wfile):
        # print '[complete_leg] %30s / %s' % (self.remote_party, self.leg_name)

        if wfile:
            wfile.write('\n%s / %s %s\n\n' % (self.remote_party, self.leg_name, '* / ' + QualityError.str(self._qual_errors) if self._qual_errors != QualityError.No else ''))

            CallLegTimeInfo.write_quality_header(wfile)

            for q in self._quality:
                q.write_to_file(wfile)

            CallLegTimeInfo.write_quality_footer(wfile)


class Call(object):
    def __init__(self, call_id, call_name):
        self.call_id = call_id
        self.call_name = call_name
        # leg_id => leg
        self.call_legs = {}
        self.file_path = BASE_DIR
        self.file = None
        self.start_time = None
        self.end_time = None

    def _write_time_range(self, wfile):
        wfile.write('[ %s - %s ] \n\n' % (self.start_time.strftime('%Y-%m-%d %H:%M:%S'), self.end_time.strftime('%Y-%m-%d %H:%M:%S')))

    def start_call(self):
        # print '[call::start] %s / %s' % (self.call_id, self.call_name)

        self.start_time = datetime.datetime.now()

        for path_dir in [str(self.start_time.year), str(self.start_time.month), str(self.start_time.day), self.call_name]:
            self.file_path += SLASH + path_dir

            if not os.path.exists(self.file_path):
                os.makedirs(self.file_path)

        self.file_path = self.file_path + SLASH + '%s___%s-%s-%s.txt' % (self.call_name, self.start_time.hour, self.start_time.minute, self.start_time.second)
        # print self.file_path
        self.file = codecs.open(self.file_path, 'w', 'utf-8')

    def complete_call(self, forced):
        # print '\n[complete_call] %s / %s' % (self.call_id, self.call_name)

        self.end_time = datetime.datetime.now()

        errors = QualityError.No

        if self.file:
            self._write_time_range(self.file)  # TODO: count participants

            for call_leg in self.call_legs.values():
                if call_leg.is_critical_quality():
                    errors |= call_leg.get_quality_errors()

                call_leg.complete_leg(self.file)

            self.file.close()

        return errors if self.file else False

    def update_call(self):
        str_call_legs = get_http_data('https://' + SERVER + '/api/v1/calls/' + str(self.call_id) + '/callLegs')

        if str_call_legs:
            xml_call_legs = ET.fromstring(str_call_legs)

            completed_leg_ids = self.call_legs.keys()

            for xml_call_leg in xml_call_legs:
                leg_id = xml_call_leg.attrib['id']
                leg_name = xml_call_leg[0].text
                remote_party = xml_call_leg[1].text

                if leg_id in self.call_legs.has_key:
                    completed_leg_ids.remove(leg_id)
                else:
                    self.call_legs[leg_id] = CallLeg(leg_id, leg_name, remote_party)

                active_leg = self.call_legs[leg_id]

                # print '  [participant] %-30s | %s %s' % (remote_party, leg_name, '*' if active_leg.is_critical_quality() else '')
                # print '  [participant] ', remote_party, '/', leg_name, '/',  leg_id

                # update CallLeg info
                active_leg.update_leg()

            # # handle completed legs
            # if len( completed_leg_ids ) > 0:
            #     print 'completed legs: ', completed_leg_ids
            #     for completed_leg_id in completed_leg_ids:
            #         completed_leg = self.call_legs[completed_leg_id]
            #         # completed_leg.complete_leg()
            #         del self.call_legs[completed_leg_id]


# call_id => Call
active_calls = {}
g_stop = False


def log_call(call, errors):
    # print '   CRIT: ', call.file_path

    summary_filepath = SLASH.join(call.file_path.split(SLASH)[:-2]) + SLASH + SUMMARY_FILENAME

    if os.path.exists(summary_filepath):
        mode = 'a'  # append if already exists
    else:
        mode = 'w'  # make a new file if not

    summary_f = codecs.open(summary_filepath, mode, 'utf-8')

    summary_f.write('[ %s ] [ %s ] %s %s\n' % (
        datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        '+' if errors == QualityError.No else '-',
        call.file_path,
        ('[ ' + QualityError.str(errors) + ' ]') if errors != QualityError.No else ''
    ))
    summary_f.close()


def save_active_calls():
    for call_id, call in active_calls.items():
        # print call_id, call.call_name
        errors = call.complete_call(True)
        log_call(call, errors)


def do_pool_stdin(arg, arg2):
    global g_stop

    print '[do_pool_stdin]\n'

    while True:
        stdin_data = sys.stdin.read(1)
        # print 'STDIN: **********************'
        # print 'STDIN: '%s'' % stdin_data
        # print 'STDIN: **********************'

        if stdin_data == 'E':
            g_stop = True
            print 'Stop pooling'
            return

        elif stdin_data == 's':
            # TODO: dump stats
            pass

    print '[do_pool_stdin] exit\n'


class myHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        def _wrap_file_to_html(path, filename, basedir):
            filepath = basedir + filename
            suffix = ''

            if not os.path.isfile(filepath) and not filename == '..':
                filename = filename + '/'
            elif os.path.isfile(filepath) and os.path.getsize(filepath) == 0:
                suffix = '&nbsp;&nbsp;<i>(empty)</i>'

            # print filename
            # print urllib.quote(filename.encode('utf-8'))

            return '<a style="padding:3px 0px 2px 10px; display:inline-block" href=' + path + urllib.quote(filename.encode('utf-8')) + '>' + filename.encode('utf-8') + '</a>' + suffix

        def _wrap_summary_to_html(txt_data):
            html_data = ''
            i = 1

            for m in re.findall(r'\[ ([^\]]+) \] (\[ (?:\+|-) \]) ([\w\W]+?.txt)(?: \[ ([^\]]+) \])?', txt_data):
                url = '/'.join(m[2].split(SLASH)[-2:])

                # html_data += m[0] + '<a style='padding:2px 0px 1px 20px; display:inline-block' href='%s'>%s</a>' % ( url, url ) + ' -- ' + m[1] + ' -- ' + m[3].lower() + '<br />'

                html_data += '%s. &nbsp; [ %s ]' % (i, m[0])
                html_data += '<span style="width:220px; display:inline-block; padding:0px 20px;">%s</span>' % m[3].lower()
                html_data += '<a style="padding:2px 0px 1px 20px; display:inline-block" href="%s">%s</a>' % (url, url) + '<br />'

                i = i + 1

            return '<html>' + html_data + '</html>'

        target = BASE_DIR + urllib.unquote(self.path).decode('utf-8').replace('/', SLASH)

        target_data = ''
        http_code = 200
        ct = 'text/plain; charset=UTF-8'

        if os.path.exists(target):
            if os.path.isfile(target):
                target_file = codecs.open(target, 'r', 'utf-8')
                target_data = target_file.read()

                filename = self.path.split('/')[-1:][0]

                if filename == SUMMARY_FILENAME:
                    ct = 'text/html; charset=UTF-8'
                    target_data = _wrap_summary_to_html(target_data)

                target_data = target_data.encode('utf-8')

            else:
                files = ['..'] + os.listdir(unicode(target))

                if SUMMARY_FILENAME in files:
                    files.remove(SUMMARY_FILENAME)
                    files = [files[0], SUMMARY_FILENAME] + files[1:]

                ct = 'text/html; charset=UTF-8'
                target_data = [
                    _wrap_file_to_html(self.path, f, target) for f in files]
                target_data = '<html><h2>Directory listing</h2>' +\
                              '<br />'.join(target_data) + '<html>'
        else:
            http_code = 404
            target_data = 'Not found'

        self.send_response(http_code)
        self.send_header('Content-type', ct)
        self.end_headers()

        # Send the html message
        self.wfile.write(target_data)


def do_handle_http(arg, arg2):
    global g_stop

    print '[do_handle_http]\n'

    server = HTTPServer(('0.0.0.0', WEB_PORT_NUMBER), myHandler)
    print 'Started httpserver on port ', WEB_PORT_NUMBER

    while not g_stop:
        # server.serve_forever()
        server.handle_request()

    server.socket.close()

    print '[do_handle_http] exit\n'


parser = argparse.ArgumentParser()
parser.add_argument(
    '-call', '--call-name', help='conference name',
    type=str, required=False)

parser.add_argument(
    '-int', '--interval', help='pool interval',
    type=int, required=False)

args = parser.parse_args()

conf_name = args.call_name if args.call_name else None
poll_interval = int(args.interval) if args.interval else POOL_TIME_SEC

# print poll_interval, conf_name


thread.start_new_thread(do_pool_stdin, (0, 0))
thread.start_new_thread(do_handle_http, (0, 0))

try:
    while not g_stop:

        """
            <calls total="1">
                <call id="90f48685-6864-4843-91e5-f269b0f702a9">
                    <name>John Smith</name>
                    <coSpace>f733a1e3-1881-439e-8c25-d26c8aa455b4</coSpace>
                    <callCorrelator>8ac38e16-fac5-4749-ad84-d994cee7bc6c</callCorrelator>
                </call>
            </calls>
        """
        str_calls = get_http_data('https://' + SERVER + '/api/v1/calls/')

        if not str_calls:
            continue

        xml_calls = ET.fromstring(str_calls)

        completed_call_ids = active_calls.keys()
        # print completedCalls

        for xml_call in xml_calls:
            call_id = xml_call.attrib['id']
            call_name = xml_call[0].text

            skip = conf_name != call_name if conf_name else False

            if skip:
                continue

            # print '\n[call] %s / %s' % (call_name, call_id)

            if call_id in active_calls:
                completed_call_ids.remove(call_id)
            else:
                # new call
                active_calls[call_id] = Call(call_id, call_name)
                active_calls[call_id].start_call()

            # update Call info
            active_call = active_calls[call_id]
            active_call.update_call()

        # handle completed calls
        if len(completed_call_ids) > 0:
            print 'completed calls: ', completed_call_ids
            for completed_call_id in completed_call_ids:
                completed_call = active_calls[completed_call_id]

                errors = completed_call.complete_call(False)
                log_call(completed_call, errors)

                del active_calls[completed_call_id]

        time.sleep(poll_interval)

        print '\n%s\n' % ('=' * 60)

    print 'Exiting..'

    save_active_calls()


except KeyboardInterrupt:
    sys.exit()
