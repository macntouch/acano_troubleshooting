#!/usr/bin/env python

import sys
import argparse
import time
import socket
import struct

from struct import unpack


MEDIA_PROTO = 17
MEDIA_PT = 100
MEDIA_D_ADDR = '10.0.3.244'
MEDIA_SSRC = 0xc585e4aa


def ip2int(addr):
    return struct.unpack('!I', socket.inet_aton(addr))[0]


def int2ip(addr):
    return socket.inet_ntoa(struct.pack('!I', addr))


# TODO: measure bitrate from Sender Reports
# TODO: calc RTT based on RR

def walk_pcap(filename):
    f_in = open(filename, 'rb')  # contains both RTP and RTCP

    magic_buf = f_in.read(4)
    assert(len(magic_buf) == 4)

    (magic,) = unpack('=L', magic_buf)
    if magic == 0xa1b2c3d4:
        swapped = '<'
    elif magic == 0xd4c3b2a1:
        swapped = '>'
    else:
        print >>sys.stderr, 'pcap magic unknown!'
        sys.exit(1)

    fhdr = f_in.read(20)
    assert(len(fhdr) == 20)
    (major, minor, zone, sigfigs, snaplen, dlt) = unpack(swapped + 'HHIIII', fhdr)

    pkt_num = 0
    rtp_cache = []

    print '    SSRC   | Receiver Report | Last seen RTP | Resume'
    print '-'*63

    while True:
        pkt_num += 1

        phdr = f_in.read(16)
        if len(phdr) == 0:
            break
        assert(len(phdr) == 16)

        (sec, usec, caplen, l) = unpack(swapped + 'IIII', phdr)
        content = f_in.read(caplen)
        assert(len(content) == caplen)

        # print caplen

        # ETH header
        (dst_mac, src_mac, typ) = unpack('!6s6sH', content[0:14])
        # print hexlify(dst_mac), hexlify(src_mac), hex(typ)

        if typ == 0x800:
            ip_offset = 14
            ip_payload_offset = ip_offset + 20

            # IPv4 header
            (ver_ihl, dscp_ecn, tot_len, frag_id, flags_fo, ttl, proto, cksum, s_addr, d_addr) = unpack('!BBHHHbbHII', content[ip_offset:ip_payload_offset])

            ip_ver = (ver_ihl & 0xF0) >> 4
            ihl = (ver_ihl & 0xF)

            if ip_ver != 4:
                continue

            # print ip_ver, ihl, dscp_ecn, tot_len, hex(frag_id), proto, s_addr, d_addr
            # if s_addr == 0xb000549 or d_addr == 0xb000549:
            #     print pkt_num, hex(s_addr), hex(d_addr)
            #     pkt_matched = True

            ihl -= 5
            if ihl:
                ip_payload_offset += ihl << 2

            if proto == MEDIA_PROTO:
                (sport, dport, length, cksum) = unpack('!HHHH', content[ip_payload_offset:ip_payload_offset+8])
                length = length - 8

                if not length >= 2:
                    continue

                udp_payload_offset = ip_payload_offset + 8
                (first_bit, pkt_type) = unpack('!BB', content[udp_payload_offset:udp_payload_offset+2])

                # print pkt_num, pkt_type, pkt_type == (MEDIA_PT | 0x80)

                if pkt_type not in [0xc8, 0xc9] and pkt_type not in [MEDIA_PT, MEDIA_PT | 0x80]:
                    continue

                # print 'UDP #%s %s --> %s [%s] [%3s bytes, cs:%-6s] [%s]' % (pkt_num, sport, dport, pkt_type, length + 8, hex(cksum), time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(sec)))
                # print ip_ver, ihl, dscp_ecn, tot_len, hex(frag_id), proto, int2ip(s_addr), int2ip(d_addr)

                if pkt_type in [0xc8, 0xc9] and int2ip(s_addr) == MEDIA_D_ADDR:
                    # SR: 28 bytes hdr
                    # RR: 8 bytes hdr
                    # rr_cnt = (first_bit & 0x1f)
                    # print pkt_type

                    if pkt_type == 0xc8:
                        rr_offset = udp_payload_offset + 28  # SR hdr size
                    elif pkt_type == 0xc9:
                        rr_offset = udp_payload_offset + 8  # RR hdr size

                    # RR header, 24 bytes
                    (rr_ssrc, rr_ssrc_data, rr_seq_num, rr_jitter, rr_sr_timestamp, rr_delay_sr_timestamp) = unpack('!IIIIII', content[rr_offset:rr_offset+24])

                    # print hex(rr_ssrc)
                    if rr_ssrc == MEDIA_SSRC:
                        # print rtp_cache
                        # print rtp_cache[-1:]
                        # print rtp_cache[-1:][0][0]
                        last_rtp_seq = rtp_cache[-1:][0][1] if len(rtp_cache) > 0 else 0
                        last_rtp_pkt_num = rtp_cache[-1:][0][0] if len(rtp_cache) > 0 else 0

                        # print pkt_num, time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(sec)), hex(rr_ssrc), rr_seq_num, last_rtp_seq, last_rtp_pkt_num
                        print '%s #%-5s RR %5s  %5s of #%-5s / %-5s [%s]' % (hex(rr_ssrc), pkt_num, rr_seq_num, last_rtp_seq, last_rtp_pkt_num, last_rtp_seq - rr_seq_num, time.strftime('%H:%M:%S', time.localtime(sec)))
                        rtp_cache = []

                elif (pkt_type == MEDIA_PT or pkt_type == (MEDIA_PT | 0x80)) and int2ip(d_addr) == MEDIA_D_ADDR:
                    rtp_offset = udp_payload_offset
                    # RTP header, 12 bytes
                    (rtp_ver, rtp_pkt_type, rtp_seq_num, rtp_timestamp, rtp_ssrc) = unpack('!BBHII', content[rtp_offset:rtp_offset+12])

                    if rtp_ssrc == MEDIA_SSRC:
                        # print rtp_seq_num
                        rtp_cache.append((pkt_num, rtp_seq_num))
            else:
                continue

    f_in.close()


parser = argparse.ArgumentParser()
parser.add_argument('-file',    help='input .pcap',     type=str, required=True)
parser.add_argument('-ssrc',    help='media SSRC',      type=str, required=True)
parser.add_argument('-daddr',   help='daddr',           type=str, required=False, default='10.0.3.244')
parser.add_argument('-pt',      help='media PT value',  type=int, required=False, default=100)


if __name__ == '__main__':
    args = parser.parse_args()

    MEDIA_SSRC = int(args.ssrc, 16)
    MEDIA_D_ADDR = args.daddr
    MEDIA_PT = args.pt

    walk_pcap(args.file)
