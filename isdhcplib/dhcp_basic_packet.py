# isdhcplib
# Copyright (c) 2013 Alexander V. Ignatyev <ialx84@ya.ru>
# Based on pydhcplib by Mathieu Ignacio -- mignacio@april.org
#
# This file is part of isdhcplib.
# Isdhcplib is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import sys
from struct import pack, unpack
from dhcp_constants import *
from type_ipv4 import ipv4
from type_strlist import strlist
from type_rfc import *


# DhcpPacket : base class to encode/decode dhcp packets.


class DHCP_DECODER(object):
    def decode(self, type_spec, data, data_len):
        if type_spec not in self._type_map:
            return data[:data_len]

        decoder = self._type_map[type_spec]

        return decoder(self, data, data_len)

    def __call__(self, *args, **kwargs):
        return self.decode(*args, **kwargs)

    def validate_len(self, type_spec, data_len):
        spec = self._spec_map.get(type_spec, None)
        if not spec:
            print "No decoder for spec: %s" % type_spec
            return False

        print type_spec, data_len

        if (spec[0] != 0 and spec[0] == data_len) \
            or (spec[1] <= data_len and data_len % spec[2] == 0):
            return True

        return False

    def _decode_char(self, data, data_len):
        # spec: fixed_len: 1, min_len: 1, multiplicator: 0
        if len(data) == 1:
            return data[:1]

        return None

    def _decode_char_plus(self, data, data_len):
        # spec: fixed_len: 0, min_len: 1, multiplicator: 1
        if len(data) >= 1:
            return data[:data_len]

        return None

    def _decode_ipv4(self, data, data_len):
        # spec: fixed_len: 4, min_len: 4, multiplicator: 0
        if len(data) == 4 and data_len == 4:
            return ipv4(data)

        return None

    def _decode_ipv4_plus(self, data, data_len):
        # spec: fixed_len: 0, min_len: 4, multiplicator: 4
        if len(data) >= 4 and data_len % 4 == 0:
            return data

        return None

    def _decode_string(self, data, data_len):
        # spec: fixed_len: 0, min_len: 1, multiplicator: 1
        if len(data) >= 1:
            return data[:data_len]

        return None

    def _decode_32_bits(self, data, data_len):
        if len(data) != 4:
            return None

        val = int(ipv4(data))
        return data

    def _decode_rfc4702(self, data, data_len):
        # spec: fixed_len: 0, min_len: 3, multiplicator: 0
        if len(data) >= 3 and data_len >= 3:
            return data[:data_len]
        return None

    def _decode_rfc3046(self, data, data_len):
        return RFC3046(data)

    def _decode_rfc3442(self, data, data_len):
        return RFC3442(data)

    _type_map = {
        "char":   _decode_char,
        "char+":  _decode_char_plus,
        "ipv4":   _decode_ipv4,
        "ipv4+":  _decode_ipv4_plus,
        "string": _decode_string,
        "32-bits": _decode_32_bits,
        #"RFC3046": _decode_rfc3046,
        #"RFC3442": _decode_rfc3442,
        #"RFC4702": _decode_rfc4702,
    }

    _spec_map = {
        "char":   [1, 1, 0],
        "char+":  [0, 0, 1],
        "ipv4":   [4, 4, 0],
        "ipv4+":  [0, 4 ,4],
        "32-bits": [4, 4, 0],
        "string": [0, 0, 1],
        #"RFC3046": None,
        #"RFC3442": None,
        #"RFC4702": [0, 3, 1],
    }


class DHCPBasicPacket(object):
    _offset_options = 236

    decoder = DHCP_DECODER()

    def __init__(self, data):
        # multimethod?
        if (not data): return False

        # init objects
        self.fields_data  = {}
        self.options_data = {}

        # calc data length
        data_len = len(data)

        # convert string to tuple of intergers
        if isinstance(data, basestring):
            # unpack to tuple of integers
            data = list(unpack("!%dB" % data_len, data))

        # packet_data is header with magic cookie
        self.fields_data  = data[:self._offset_options + 4]
        self.options_data = self._DecodeOptions(data, data_len)


    def _DecodeOptions(self, data, data_len):
        # lookup magic cookie. ideally it should be found exactly after fields.
        # but as reported some clients can make offset before magic cookie
        offset = self._offset_options
        options = {}

        # iterate through data
        while (offset < data_len):
            if data[offset:offset+4] == MAGIC_COOKIE: 
                break
            
            #print "MAGIC COOKIE NOT FOUND:", offset
            offset += 1
        
        # set offset after magic cookie
        offset += 4
        # last found option
        last_option = None

        # parse options
        while (offset < data_len):
            option_start = option_end = offset

            if data[offset] == 255:
                break
            elif data[offset] == 0:
                if last_option:
                    last_option_data = options[last_option]
                    last_option[3] += [0]
                offset += 1
                continue
            else:
                # parse option header
                option, option_len = data[option_start:option_start + 2]

                # calculate position of last option byte
                option_end = option_start + option_len + 2

                # get option data
                option_data = data[option_start + 2:option_end]

                # update offset
                offset = option_end

                # pase option data
                name, option_type = DHCP_OPTIONS.get(option, (None, None))

                if not name or not option_type:
                    print "Unknown DHCP OPTION: %s" % option
                    continue

                options[name] = (option, option_type, option_len, option_data)
                last_option = name

        return options

    def cache(func):
        def wrapper(*args, **kwargs):
            cls, option_name = args

            # check if cache object exists
            if not getattr(cls, "_cache", None):
                setattr(cls, "_cache", {})

            # try to get value from cache
            if option_name not in cls._cache: 
                cls._cache[option_name] = func(*args, **kwargs)

            return cls._cache[option_name]
        return wrapper

    def uncache(func):
        def wrapper(*args, **kwargs):
            cls, option_name = args

            # check if cache object exists
            cache = getattr(cls, "_cache", {})

            if option_name in cache: 
                del cache[option_name]

            return func(*args, **kwargs)
        return wrapper

    @cache
    def GetOption(self, name):
        # Requested field
        if name in DHCP_FIELDS:
            # Get option data
            pos, option_len, option_type = DHCP_FIELDS[name]
            option_data = self.fields_data[pos:pos + option_len]
        # Requested option
        elif name in self.options_data:
            # Get option data
            option_num, option_type, option_len, option_data = self.options_data[name]
        else:
            return None
        
        # Decode & return result
        return self.decoder(option_type, option_data, option_len)

    @uncache
    def DeleteOption(self, name):
        # Requested field
        if name in DHCP_FIELDS:
            # Get option data
            pos, option_len, option_type = DHCP_FIELDS[name]
            self.fields_data[pos:pos + option_len] = [0] * option_len
            return True
        # Requested option
        elif name in self.options_data:
            # Get option data
            if name in self.options_data:
                del self.options_data[name]
                return True
        else:
            return False
        
        # Decode & return result
        return False

    def SetOption(self, name, value):
        if name in DHCP_FIELDS:
            # validate value
            pos, field_len, field_type = DHCP_FIELDS[name]

            if len(value) != field_len:
                print "Wrong value=%d for field %s. Expected %d" % (len(value), name, field_len)
                return False

            self.fields_data[pos:pos + field_len] = value
            return True
        # Requested options
        elif name in DHCP_OPTION_NUM:
            # Get option data
            option_num = DHCP_OPTION_NUM[name]

            option_name, option_type = DHCP_OPTIONS[option_num]
            if self.decoder.validate_len(option_type, len(value)):
                self.options_data[name] = (option_num, option_type, len(value), value)
                return True

        else:
            print "Unknown option: %s" % name
            return False


    @property
    def IsDhcpPacket(self):
        return self.fields_data[236:240] == MAGIC_COOKIE

    def IsOption(self, name):
        return (name in DHCP_FIELDS) or (name in self.options_data)

    def EncodePacket(self):
        # MUST set options in order to respect the RFC (see router option)
        head_options, tail_options, options = [], [], []

        for option_name, option in self.options_data.iteritems():
            payload = [option[0], option[2]]    # type, len
            payload += option[3]                # raw value

            if option[0] in HEAD_OPTIONS:
                head_options += payload
            elif option[0] in TAIL_OPTIONS:
                tail_options += payload
            else:
                options += payload

        options = head_options + options + tail_options

        # concatenate fields & options
        packet = list(self.fields_data[:240]) + options

        # end packet with <FF>
        packet.append(255)

        # caluculate packet length      // hi, cap
        packet_len = len(packet)

        return pack("%dB" % packet_len, *packet)
