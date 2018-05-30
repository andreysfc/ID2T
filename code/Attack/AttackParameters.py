import enum


class Parameter(enum.Enum):
    """
    Defines the shortname for attack parameters. The shortname may be used for attack parameter specification
    when calling Core via the command line.
    """
    # recommended type: (list/range of) IP address(es)------------------------------------------------------------------
    IP_SOURCE = 'ip.src'  # source IP address(es)
    IP_DESTINATION = 'ip.dst'  # destination IP address(es)
    IP_DNS = 'ip.dns'  # IP address of DNS server
    IP_VICTIM = 'ip.victim'  # victim IP address (only needed for indirect attacks)
    HOSTING_IP = 'hosting.ip'  # IP address(es) hosting the vulnerable service
    # recommended type: MAC address ------------------------------------------------------------------------------------
    MAC_SOURCE = 'mac.src'  # MAC address of source
    MAC_DESTINATION = 'mac.dst'  # MAC address of destination
    # recommended type: Port -------------------------------------------------------------------------------------------
    PORT_DESTINATION = 'port.dst'  # destination ports
    PORT_SOURCE = 'port.src'  # source ports
    PORT_OPEN = 'port.open'  # open ports
    # recommended type: Integer positive -------------------------------------------------------------------------------
    PACKETS_LIMIT = 'packets.limit'
    NUMBER_ATTACKERS = 'attackers.count'
    ATTACK_DURATION = 'attack.duration'  # in seconds
    VICTIM_BUFFER = 'victim.buffer'  # in packets
    TARGET_URI = 'target.uri'
    NUMBER_INITIATOR_BOTS = 'bots.count'
    INTERVAL_SELECT_START = 'interval.selection.start'
    INTERVAL_SELECT_END = 'interval.selection.end'
    TARGET_COUNT = "target.count"  # count of target IP addresses
    # recommended type: domain -----------------------------------------------------------------------------------------
    TARGET_HOST = 'target.host'
    # recommended type: Float ------------------------------------------------------------------------------------------
    PACKET_LIMIT_PER_SECOND = 'packet.limit-per-second'  # packets per second
    INJECT_PPS = 'inject.pps'  # packets per seconds injected by the attack
    INJECT_AT_TIMESTAMP = 'inject.at-timestamp'  # unix epoch time (seconds.millis) where attack should be injected
    # recommended type: Packet Position --------------------------------------------------------------------------------
    INJECT_AFTER_PACKET = 'inject.after-pkt'  # packet after which attack should be injected
    # recommended type: boolean  ---------------------------------------------------------------------------------------
    PORT_DEST_SHUFFLE = 'port.dst.shuffle'  # shuffles the destination ports if a list of ports is given
    PORT_DEST_ORDER_DESC = 'port.dst.order-desc'  # uses a descending port order instead of a ascending order
    IP_SOURCE_RANDOMIZE = 'ip.src.shuffle'  # randomizes the sources IP address if a list of IP addresses is given
    PORT_SOURCE_RANDOMIZE = 'port.src.shuffle'  # randomizes the source port if a list of sources ports is given
    NAT_PRESENT = 'nat.present'  # if NAT is active, external computers cannot initiate a communication in MembersMgmtCommAttack
    TTL_FROM_CAIDA = 'ttl.from-caida'  # if True, TTLs are assigned based on the TTL distributions from the CAIDA dataset
    PORT_MULTI = "port.multi"  # select destination port as an ephemeral port if True, calculate the destination port based on the hostname, otherwise
    PACKETS_MARK = "packets.mark"  # indicating if the attack will mark generated packets
    # recommended type: file path --------------------------------------------------------------------------------------
    FILE_CSV = 'file.csv'  # file path to CSV containing a communication pattern
    FILE_XML = 'file.xml'  # file path to XML containing a communication pattern
    CUSTOM_PAYLOAD_FILE = 'custom.payload.file'  # file that contains custom payload for ftp exploits
    # recommended type: CommType ---------------------------------------------------------------------------------------
    COMM_TYPE = "comm.type"  # the locality of bots in botnet communication (e.g. local, external, mixed)
    # recommended type: Percentage (0.0-1.0) ---------------------------------------------------------------------------
    IP_REUSE_TOTAL = 'ip.reuse.total'  # percentage of IPs in original PCAP to be reused
    IP_REUSE_LOCAL = 'ip.reuse.local'  # percentage of private IPs in original PCAP to be reused
    IP_REUSE_EXTERNAL = 'ip.reuse.external'  # percentage of public IPs in original PCAP to be reused
    HOSTING_PERCENTAGE = 'hosting.percentage'  # percentage of target IPs hosting the vulnerable service
    # recommended type: Positive Integer between 0 and 100 -------------------------------------------------------------
    PACKET_PADDING = 'packet.padding'
    # recommended type: interval selection strategy, i.e. 'random', 'optimal' or 'custom' ------------------------------
    INTERVAL_SELECT_STRATEGY = 'interval.selection.strategy'
    # recommended type: version number (string)
    PROTOCOL_VERSION = 'protocol.version'  # version of the protocol to be used
    HOSTING_VERSION = 'hosting.version'  # version of the protocol being hosted on targets
    # recommended type: platform abridgement, i.e. 'Win7', 'WinXP' or 'linux'
    SOURCE_PLATFORM = 'src.platform'  # the operating system used by attacker aka source
    # recommended type: string
    CUSTOM_PAYLOAD = 'custom.payload'  # custom payload for ftp exploits


class ParameterTypes(enum.Enum):
    """
    Defines types for parameters. These types may be used in the specification of allowed parameters within the
    individual attack classes. The type is used to verify the validity of the given value.
    """
    TYPE_IP_ADDRESS = 0
    TYPE_MAC_ADDRESS = 1
    TYPE_PORT = 2
    TYPE_INTEGER_POSITIVE = 3
    TYPE_TIMESTAMP = 4
    TYPE_BOOLEAN = 5
    TYPE_FLOAT = 6
    TYPE_PACKET_POSITION = 7  # used to derive timestamp from parameter INJECT_AFTER_PACKET
    TYPE_DOMAIN = 8
    TYPE_STRING = 9
    TYPE_FILEPATH = 10
    TYPE_PERCENTAGE = 11
    TYPE_PADDING = 12
    TYPE_INTERVAL_SELECT_STRAT = 13