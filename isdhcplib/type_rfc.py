#-*- coding: utf-8 -*-
from netaddr import IPAddress, IPNetwork

class RFC3046(object):
    """
    The Relay Agent Information Option protocol extension (RFC 3046, usually referred to in the industry by its
    actual number as Option 82) allows network operators to attach tags to DHCP messages as these messages
    arrive on the network operator's trusted network. This tag is then often used as an authorization token to
    control the client's access to network resources.
    """

    def __init__(self, data):
        """
        Constructor.

        :param data: DHCP option 82 field value as byte array

        """

        self.agent_circuit_id = self.agent_remote_id = []

        # Keep raw data for future use
        self.raw = data

        # Decode suboptions
        self.suboptions = self._parseSuboption(data)

        # Decode well-known suboptions attributes:
        #   1 - Agent Circuit ID
        #   2 - Agent Remote ID
        for suboption_id, suboption_value in self.suboptions.iteritems():
            if suboption_id == 1:
                self.agent_circuit_id = self._decodeSuboptionAttr(suboption_value)
            elif suboption_id == 2:
                self.agent_remote_id = self._decodeSuboptionAttr(suboption_value)


    def _parseSuboption(self, data):
        """
        Decode suboptions from raw byte array. The Agent Information field consists of a sequence of
        SubOpt/Length/Value tuples for each sub-option, encoded in the following manner:

          SubOpt  Len    Sub-option Value
         +------+------+------+------+------+------+--...-+------+
         |  1   |   N  |  s1  |  s2  |  s3  |  s4  |      |  sN  |
         +------+------+------+------+------+------+--...-+------+

        Raises `ValueError` if suboption mismatch specified format.

        :param data: raw byte array

        :returns: Dictionary with suboption ID as keys and suboption values as values
        """

        if len(data) < 2: raise ValueError('Suboption decode failed. Expected at least 2 bytes, got %s bytes' % len(data))

        # First 2 bytes expected to be suboption id & suboption value length
        suboption_id, suboption_len = data[:2]

        suboption_value = data[2:2+suboption_len]

        # Make sure if suboption complains RC 3046 suboption format
        if len(suboption_value) != suboption_len:
            raise ValueError('Suboption format mismatch. Suboption id = %s, expected length = %s, length = %s' %
                             (suboption_id, suboption_len, len(suboption_value)))

        suboption = {suboption_id: suboption_value}

        # Recursively parse suboptions
        if len(data) > suboption_len + 2:
            suboption.update(self._parseSuboption(data[2+suboption_len:]))

        return suboption


    def _decodeSuboptionAttr(self, suboption_value):
        """
        Agent Relay suboption format:

        +------------+-----------+-------------------------+
        | Attr Type  | Attr Len  |  Attr Value             |
        +============+===========+======+======+=====+=====+
        |      X     |     N     |  a1  |  a2  | ... | aN  |
        +------------+-----------+------+------+-----+-----+

        """

        # Expecting non-empty array
        if len(suboption_value) < 2: return []

        suboption_attr_type, suboption_attr_len = suboption_value[0:2]

        suboption_attr = [(suboption_attr_type, suboption_value[2:2 + suboption_attr_len])]

        if len(suboption_value) > suboption_attr_len + 2:
            suboption_attr.extend(self._decodeSuboptionAttr(suboption_value[2 + suboption_attr_len:]))

        return suboption_attr


    @property
    def AgentRemoteId(self):
        if len(self.agent_remote_id) == 0: return None

        remote_id_type, remote_id = self.agent_remote_id[0]

        if remote_id_type == 0 and len(remote_id) == 6:
            return remote_id
        if remote_id_type == 1 and len(remote_id) == 17:
            # buggy D-Link option 82
            remote_id = [chr(i) for i in remote_id if i != 45]
            remote_id = [int(''.join(pair), 16) for pair in zip(remote_id[::2], remote_id[1::2])]

            return remote_id

        return None


    @property
    def AgentCircuitId(self):
        if len(self.agent_circuit_id) == 0: return None

        attr_type, attr_value = self.agent_circuit_id[0]

        if attr_type == 0 and len(attr_value) == 4:
            # D-Link circuit ID format
            vlan = (attr_value[0] << 8) + attr_value[1]
            module = attr_value[2]
            port = attr_value[3]

            return vlan, module, port

        return None


    def __nonzero__(self):
        return len(self.raw) > 0


    def __len__(self):
        return len(self.raw)



class RFC3442:
    def __init__(self, routes):
        self._routes = []
        for subnet, gw in routes.iteritems():
            self._routes.append((IPNetwork(subnet).network, IPNetwork(subnet).prefixlen, 
                        IPNetwork(subnet).network.words, IPAddress(gw).words))

    def ListClasslessRoutes(self):
        result = []

        for route in self._routes:
            result.append(route[1])
            for i in xrange(4):
                if route[1] > i * 8:
                    result.append(route[2][i])

            result.extend(route[3])

        return result

