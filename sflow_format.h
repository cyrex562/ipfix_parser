/* Address types */

typedef opaque ip_v4[4];
typedef opaque ip_v6[16];

enum address_type {
   UNKNOWN  = 0,
   IP_V4    = 1,
   IP_V6    = 2
}

union address (address_type type) {
   case UNKNOWN:
     void;
   case IP_V4:
     ip_v4;
   case IP_V6:
     ip_v6;
}

/* Data Format
     The data_format uniquely identifies the format of an opaque structure in
     the sFlow specification. A data_format is contructed as follows:
       - The most significant 20 bits correspond to the SMI Private Enterprise
         Code of the entity responsible for the structure definition. A value
         of zero is used to denote standard structures defined by sflow.org.
       - The least significant 12 bits are a structure format number assigned
         by the enterprise that should uniquely identify the the format of the
         structure.

     There are currently three opaque structures where which data_formats
      are used:
       1. sample_data
       2. counter_data
       3. flow_data

     Structure format numbers may be re-used within each of these contexts.
     For example, an (inmon,1) data_format could identify a particular
     set of counters when used to describe counter_data, but refer to
     a set of flow attributes when used to describe flow_data.

     An sFlow implementor should use the standard structures
     where possible, even if they can only be partially
     populated. Vendor specific structures are allowed, but
     should only be used to supplement the existing
     structures, or to carry information that hasn't yet
     been standardized.

     Enterprises are encouraged to publish structure definitions in
     XDR format to www.sflow.org. A structure description document should
     contain an XDR structure definition immediately preceded by a comment
     listing the structure to which it applies, the enterprise number, and
     the structure number. See the definitions of counter_sample and
     flow_sample for examples.

     Note: An enterprise which has defined sFlow structures is
           permitted to extend those structure definitions at the end
           without changing structure numbers.  Any changes that would
           alter or invalidate fields in published structure
           definitions must be implemented using a new structure
           number.  This policy allows additional data to be added to
           structures while still maintaining backward compatibility.
           Applications receiving sFlow data must always use the
           opaque length information when decoding opaque<> structures
           so that encountering extended structures will not cause
           decoding errors. Note that these rules apply to the
           standard structures as well. */

typedef unsigned int data_format;

/* sFlowDataSource encoded as follows:
     The most significant byte of the source_id is used to indicate the type
     of sFlowDataSource:
        0 = ifIndex
        1 = smonVlanDataSource
        2 = entPhysicalEntry
     The lower three bytes contain the relevant index value. */

typedef unsigned int sflow_data_source;

/* Input/output port information
     Encoding of interface(s) involved in the packet's path through
     the device.

     0 if interface is not known.
     The most significant 2 bits are used to indicate the format of
     the 30 bit value.

        - format = 0 single interface
            value is ifIndex of the interface. The maximum value,
            0x3FFFFFFF, indicates that there is no input or output
            interface (according to which field it appears in).
            This is used in describing traffic which is not
            bridged, routed, or otherwise sent through the device
            being monitored by the agent, but which rather
            originates or terminates in the device itself.  In
            the input field, this value is used to indicate
            packets for which the origin was the device itself
            (e.g. a RIP request packet sent by the device, if it
            is acting as an IP router).  In the output field,
            this value is used to indicate packets for which the
            destination was the device itself (e.g. a RIP
            response packet (whether unicast or not) received by
            the device, if it is acting as an IP router).

        - format = 1 packet discarded
            value is a reason code. Currently the following codes
            are defined:
                0 - 255 use ICMP Destination Unreachable codes
                        See www.iana.org for authoritative list.
                        RFC 1812, section 5.2.7.1 describes the
                        current codes.  Note that the use of
                        these codes does not imply that the
                        packet to which they refer is an IP
                        packet, or if it is, that an ICMP message
                        of any kind was generated for it.
                        Current value are:
                          0  Net Unreachable
                          1  Host Unreachable
                          2  Protocol Unreachable
                          3  Port Unreachable
                          4  Fragmentation Needed and
                             Don't Fragment was Set
                          5  Source Route Failed
                          6  Destination Network Unknown
                          7  Destination Host Unknown
                          8  Source Host Isolated
                          9  Communication with Destination
                             Network is Administratively
                             Prohibited
                         10  Communication with Destination Host
                             is Administratively Prohibited
                         11  Destination Network Unreachable for
                             Type of Service
                         12  Destination Host Unreachable for
                             Type of Service
                         13  Communication Administratively
                             Prohibited
                         14  Host Precedence Violation
                         15  Precedence cutoff in effect
                256 = unknown
                257 = ttl exceeded
                258 = ACL
                259 = no buffer space
                260 = RED
                261 = traffic shaping/rate limiting
                262 = packet too big (for protocols that don't
                      support fragmentation)

             Note: Additional reason codes may be published over
                   time. An application receiving sFlow must be
                   prepared to accept additional reason codes.
                   The authoritative list of reason codes will
                   be maintained at www.sflow.org

        - format = 2 multiple destination interfaces
            value is the number of interfaces. A value of 0
            indicates an unknown number greater than 1.

      Note: Formats 1 & 2 apply only to an output interface and
            never to an input interface. A packet is always
            received on a single (possibly unknown) interface.

      Examples:
         0x00000002  indicates ifIndex = 2
         0x00000000  ifIndex unknown.
         0x40000001  packet discarded because of ACL.
         0x80000007  indicates a packet sent to 7 interfaces.
         0x80000000  indicates a packet sent to an unknown number
                     of interfaces greater than 1. */

typedef unsigned int interface;

/* Counter and Flow sample formats

   Compact and expand forms of counter and flow samples are defined.
   An agent must not mix compact/expanded encodings.  If an agent
   will never use ifIndex numbers >= 2^24 then it must use compact
   encodings for all interfaces.  Otherwise the expanded formats must
   be used for all interfaces.

   While the theoretical range of ifIndex numbers is 2^32,
   RFC 2863 recommends that ifIndex numbers are allocated using small
   integer values starting at 1. For most agent implementations the
   2^24 range of values for ifIndex supported by the compact encoding
   is more than adequate and its use saves bandwidth. The expanded
   encodings are provided to support the maximum possible values
   for ifIndex, even though large ifIndex values are not encouraged. */

struct flow_record {
   data_format flow_format;         /* The format of sflow_data */
   opaque flow_data<>;              /* Flow data uniquely defined
                                       by the flow_format. */
}

struct counter_record {
   data_format counter_format;     /* The format of counter_data */
   opaque counter_data<>;          /* A block of counters uniquely defined
                                      by the counter_format. */
}

/* Compact Format Flow/Counter samples
      If ifIndex numbers are always < 2^24 then the compact
      must be used. */

/* Format of a single flow sample */
/* opaque = sample_data; enterprise = 0; format = 1 */

struct flow_sample {
   unsigned int sequence_number;  /* Incremented with each flow sample
                                     generated by this source_id.
                                     Note: If the agent resets the
                                           sample_pool then it must
                                           also reset the sequence_number.*/
   sflow_data_source source_id;   /* sFlowDataSource */
   unsigned int sampling_rate;    /* sFlowPacketSamplingRate */
   unsigned int sample_pool;      /* Total number of packets that could have
                                     been sampled (i.e. packets skipped by
                                     sampling process + total number of
                                     samples) */
   unsigned int drops;            /* Number of times that the sFlow agent
                                     detected that a packet marked to be
                                     sampled was dropped due to
                                     lack of resources. The drops counter
                                     reports the total number of drops
                                     detected since the agent was last reset.
                                     A high drop rate indicates that the
                                     management agent is unable to process
                                     samples as fast as they are being
                                     generated by hardware. Increasing
                                     sampling_rate will reduce the drop
                                     rate. Note: An agent that cannot
                                     detect drops will always report
                                     zero. */

   interface input;               /* Interface packet was received on. */
   interface output;              /* Interface packet was sent on. */

   flow_record flow_records<>;    /* Information about a sampled packet */
}

/* Format of a single counter sample */
/* opaque = sample_data; enterprise = 0; format = 2 */

struct counters_sample {
   unsigned int sequence_number;   /* Incremented with each counter sample
                                      generated by this source_id
                                      Note: If the agent resets any of the
                                            counters then it must also
                                            reset the sequence_number.
                                            In the case of ifIndex-based
                                            source_id's the sequence
                                            number must be reset each time
                                            ifCounterDiscontinuityTime
                                            changes. */
   sflow_data_source source_id;    /* sFlowDataSource */
   counter_record counters<>;      /* Counters polled for this source */
}


/* Format of a sample datagram */

struct sample_record {
   data_format sample_type;       /* Specifies the type of sample data */
   opaque sample_data<>;          /* A structure corresponding to the
                                     sample_type */
}

/* Header information for sFlow version 5 datagrams

   The sub-agent field is used when an sFlow agent is implemented on a
   distributed architecture and where it is impractical to bring the
   samples to a single point for transmission.

   However, it is strongly recommended that wherever possible the sub-agent
   mechanism not be used. If multiple processors are available within a device
   the various tasks associated with creating flow and counter samples can be
   distributed among the processors. However, the agent should be architected
   so that all the samples are marshalled into a single datagram stream. The
   final marshalling task involved very little processing, but has important
   benefits in making the overall sFlow system scalable. By reducing the
   number of UDP packets and packet streams, the protocol overheads associated
   with sFlow are significantly reduced at the receiver.

   Each sFlowDataSource must be associated with only one sub-agent. The
   association between sFlowDataSource and sub-agent must remain
   constant for the entire duration of an sFlow session. */

struct sample_datagram_v5 {
   address agent_address          /* IP address of sampling agent,
                                     sFlowAgentAddress. */
   unsigned int sub_agent_id;     /* Used to distinguishing between datagram
                                     streams from separate agent sub entities
                                     within an device. */
   unsigned int sequence_number;  /* Incremented with each sample datagram
                                     generated by a sub-agent within an
                                     agent. */
   unsigned int uptime;           /* Current time (in milliseconds since device
                                     last booted). Should be set as close to
                                     datagram transmission time as possible.
                                     Note: While a sub-agents should try and
                                           track the global sysUptime value
                                           a receiver of sFlow packets must
                                           not assume that values are
                                           synchronised between sub-agents. */
   sample_record samples<>;        /* An array of sample records */
}

enum datagram_version {
   VERSION5 = 5
}

union sample_datagram_type (datagram_version version) {
   case VERSION5:
      sample_datagram_v5 datagram;
}

struct sample_datagram {
   sample_datagram_type version;
}


//    An sFlow Datagram contains lists of Packet Flow Records and counter
//    records.  The format of each Packet Flow Record is identified by a
//    data_format value.  The data_format name space is extensible,
//    allowing for the addition of standard record types as well as vendor
//    specific extensions.

//    A number of standard record types have been defined. However, an
//    sFlow Agent is not required to support all the different record
//    types, only those applicable to its treatment of the particular
//    packet being reporting on. For example, a layer 2 switch will not
//    report on subnet information since it is not performing a routing
//    function. A layer 2/3 switch will report layer 2 information for
//    packets it switches, and layer 2 and 3 information for packets it
//    routes.

//    The following is an XDR description of the standard set of data
//    records that can be carried in sFlow Datagrams:

/* Enterprise = 0 refers to standard sFlow structures. An
   sFlow implementor should use the standard structures
   where possible, even if they can only be partially
   populated. Vendor specific structures are allowed, but
   should only be used to supplement the existing
   structures, or to carry information that hasn't yet
   been standardized.

   The following values should be used for fields that are
   unknown (unless otherwise indicated in the structure
   definitions).
      - Unknown integer value. Use a value of 0 to indicate that
        a value is unknown.
      - Unknown counter. Use the maximum counter value to indicate
        that the counter is not available. Within any given sFlow
        session a particular counter must be always available, or
        always unavailable. An available counter may temporarily
        have the max value just before it rolls to zero. This is
        permitted.
      - Unknown string. Use the zero length empty string. */


/* Flow Data Types

   A flow_sample must contain packet header information. The
   prefered format for reporting packet header information is
   the sampled_header. However, if the packet header is not
   available to the sampling process then one or more of
   sampled_ethernet, sampled_ipv4, sampled_ipv6 may be used. */

/* Packet Header Data */

/* The header_protocol enumeration may be expanded over time.
   Applications receiving sFlow must be prepared to receive
   sampled_header structures with unknown sampled_header values.

   The authoritative list of protocol numbers will be maintained
   at www.sflow.org */

enum header_protocol {
   ETHERNET-ISO88023    = 1,
   ISO88024-TOKENBUS    = 2,
   ISO88025-TOKENRING   = 3,
   FDDI                 = 4,
   FRAME-RELAY          = 5,
   X25                  = 6,
   PPP                  = 7,
   SMDS                 = 8,
   AAL5                 = 9,
   AAL5-IP              = 10, /* e.g. Cisco AAL5 mux */
   IPv4                 = 11,
   IPv6                 = 12,
   MPLS                 = 13,
   POS                  = 14  /* RFC 1662, 2615 */
}

/* Raw Packet Header */
/* opaque = flow_data; enterprise = 0; format = 1 */

struct sampled_header {
   header_protocol protocol;       /* Format of sampled header */
   unsigned int frame_length;      /* Original length of packet before
                                      sampling.
                                      Note: For a layer 2 header_protocol,
                                            length is total number of octets
                                            of data received on the network
                                            (excluding framing bits but
                                            including FCS octets).
                                            Hardware limitations may
                                            prevent an exact reporting
                                            of the underlying frame length,
                                            but an agent should attempt to
                                            be as accurate as possible. Any
                                            octets added to the frame_length
                                            to compensate for encapsulations
                                            removed by the underlying hardware
                                            must also be added to the stripped
                                            count. */

   unsigned int stripped;          /* The number of octets removed from
                                      the packet before extracting the
                                      header<> octets. Trailing encapsulation
                                      data corresponding to any leading
                                      encapsulations that were stripped must
                                      also be stripped. Trailing encapsulation
                                      data for the outermost protocol layer
                                      included in the sampled header must be
                                      stripped.

                                      In the case of a non-encapsulated 802.3
                                      packet stripped >= 4 since VLAN tag
                                      information might have been stripped off
                                      in addition to the FCS.

                                      Outer encapsulations that are ambiguous,
                                      or not one of the standard header_protocol
                                      must be stripped. */
   opaque header<>;                /* Header bytes */
}

typedef opaque mac[6];

/* Ethernet Frame Data */
/* opaque = flow_data; enterprise = 0; format = 2 */

struct sampled_ethernet {
     unsigned int length;   /* The length of the MAC packet received on the
                               network, excluding lower layer encapsulations
                               and framing bits but including FCS octets */
     mac src_mac;           /* Source MAC address */
     mac dst_mac;           /* Destination MAC address */
     unsigned int type;     /* Ethernet packet type */
}

/* Packet IP version 4 data */
/* opaque = flow_data; enterprise = 0; format = 3 */

struct sampled_ipv4 {
   unsigned int length;     /* The length of the IP packet excluding
                               lower layer encapsulations */
   unsigned int protocol;   /* IP Protocol type
                               (for example, TCP = 6, UDP = 17) */
   ip_v4 src_ip;            /* Source IP Address */
   ip_v4 dst_ip;            /* Destination IP Address */
   unsigned int src_port;   /* TCP/UDP source port number or equivalent */
   unsigned int dst_port;   /* TCP/UDP destination port number or equivalent */
   unsigned int tcp_flags;  /* TCP flags */
   unsigned int tos;        /* IP type of service */
}

/* Packet IP Version 6 Data */
/* opaque = flow_data; enterprise = 0; format = 4 */

struct sampled_ipv6 {
   unsigned int length;     /* The length of the IP packet excluding
                               lower layer encapsulations */
   unsigned int protocol;   /* IP next header
                               (for example, TCP = 6, UDP = 17) */
   ip_v6 src_ip;            /* Source IP Address */
   ip_v6 dst_ip;            /* Destination IP Address */
   unsigned int src_port;   /* TCP/UDP source port number or equivalent */
   unsigned int dst_port;   /* TCP/UDP destination port number or equivalent */
   unsigned int tcp_flags;  /* TCP flags */
   unsigned int priority;   /* IP priority */
}


/* Extended Flow Data

   Extended data types provide supplimentary information about the
   sampled packet. All applicable extended flow records should be
   included with each flow sample. */

/* Extended Switch Data */
/* opaque = flow_data; enterprise = 0; format = 1001 */
/* Note: For untagged ingress ports, use the assigned vlan and priority
         of the port for the src_vlan and src_priority values.
         For untagged egress ports, use the values for dst_vlan and
         dst_priority that would have been placed in the 802.Q tag
         had the egress port been a tagged member of the VLAN instead
         of an untagged member. */

struct extended_switch {
   unsigned int src_vlan;     /* The 802.1Q VLAN id of incoming frame */
   unsigned int src_priority; /* The 802.1p priority of incoming frame */
   unsigned int dst_vlan;     /* The 802.1Q VLAN id of outgoing frame */
   unsigned int dst_priority; /* The 802.1p priority of outgoing frame */
}

/* IP Route Next Hop
   ipForwardNextHop (RFC 2096) for IPv4 routes.
   ipv6RouteNextHop (RFC 2465) for IPv6 routes. */

typedef next_hop address;

/* Extended Router Data */
/* opaque = flow_data; enterprise = 0; format = 1002 */

struct extended_router {
   next_hop nexthop;            /* IP address of next hop router */
   unsigned int src_mask_len;   /* Source address prefix mask
                                   (expressed as number of bits) */
   unsigned int dst_mask_len;   /* Destination address prefix mask
                                   (expressed as number of bits) */
}

enum as_path_segment_type {
   AS_SET      = 1,            /* Unordered set of ASs */
   AS_SEQUENCE = 2             /* Ordered set of ASs */
}

union as_path_type (as_path_segment_type) {
   case AS_SET:
      unsigned int as_set<>;
   case AS_SEQUENCE:
      unsigned int as_sequence<>;
}

/* Extended Gateway Data */
/* opaque = flow_data; enterprise = 0; format = 1003 */

struct extended_gateway {
   next_hop nexthop;           /* Address of the border router that should
                                  be used for the destination network */
   unsigned int as;            /* Autonomous system number of router */
   unsigned int src_as;        /* Autonomous system number of source */
   unsigned int src_peer_as;   /* Autonomous system number of source peer */
   as_path_type dst_as_path<>; /* Autonomous system path to the destination */
   unsigned int communities<>; /* Communities associated with this route */
   unsigned int localpref;     /* LocalPref associated with this route */
}

/* Character Set
     MIBEnum value of character set used to encode a string - See RFC 2978
     Where possible UTF-8 encoding (MIBEnum=106) should be used. A value
     of zero indicates an unknown encoding. */

typedef unsigned int charset;

/* Extended User Data */
/* opaque = flow_data; enterprise = 0; format = 1004 */

struct extended_user {
   charset src_charset;        /* Character set for src_user */
   opaque src_user<>;          /* User ID associated with packet source */
   charset dst_charset;        /* Character set for dst_user */
   opaque dst_user<>;          /* User ID associated with packet destination */
}

enum url_direction {
   src    = 1,                 /* Source address is server */
   dst    = 2                  /* Destination address is server */
}

/* Extended URL Data */
/* opaque = flow_data; enterprise = 0; format = 1005 */

struct extended_url {
   url_direction direction;    /* Direction of connection */
   string url<>;               /* The HTTP request-line (see RFC 2616) */
   string host<>;              /* The host field from the HTTP header */
}

/* MPLS label stack
    - Empty stack may be returned if values unknown
    - If only innermost label is known then stack may contain single entry
    - See RFC 3032 for label encoding
    - Labels in network order */
typedef int label_stack<>;

/* Extended MPLS Data */
/* opaque = flow_data; enterprise = 0; format = 1006 */

struct extended_mpls {
   next_hop nexthop;           /* Address of the next hop */
   label_stack in_stack;       /* Label stack of received packet */
   label_stack out_stack;      /* Label stack for transmitted packet */
}

/* Extended NAT Data
   Packet header records report addresses as seen at the sFlowDataSource.
   The extended_nat structure reports on translated source and/or destination
   addesses for this packet. If an address was not translated it should
   be equal to that reported for the header. */
/* opaque = flow_data; enterprise = 0; format = 1007 */

struct extended_nat {
     address src_address;            /* Source address */
     address dst_address;            /* Destination address */
}

/* Extended MPLS Tunnel */
/* opaque = flow_data; enterprise = 0; format = 1008 */

struct extended_mpls_tunnel {
   string tunnel_lsp_name<>;   /* Tunnel name */
   unsigned int tunnel_id;     /* Tunnel ID */
   unsigned int tunnel_cos;    /* Tunnel COS value */
}

/* Extended MPLS VC */
/* opaque = flow_data; enterprise = 0; format = 1009 */

struct extended_mpls_vc {
   string vc_instance_name<>;  /* VC instance name */
   unsigned int vll_vc_id;     /* VLL/VC instance ID */
   unsigned int vc_label_cos;  /* VC Label COS value */
}

/* Extended MPLS FEC
    - Definitions from MPLS-FTN-STD-MIB mplsFTNTable */
/* opaque = flow_data; enterprise = 0; format = 1010 */

struct extended_mpls_FTN {
   string mplsFTNDescr<>;
   unsigned int mplsFTNMask;
}

/* Extended MPLS LVP FEC
    - Definition from MPLS-LDP-STD-MIB mplsFecTable
    Note: mplsFecAddrType, mplsFecAddr information available
          from packet header */
/* opaque = flow_data; enterprise = 0; format = 1011 */

struct extended_mpls_LDP_FEC {
   unsigned int mplsFecAddrPrefixLength;
}

/* Extended VLAN tunnel information
   Record outer VLAN encapsulations that have
   been stripped. extended_vlantunnel information
   should only be reported if all the following conditions are satisfied:
     1. The packet has nested vlan tags, AND
     2. The reporting device is VLAN aware, AND
     3. One or more VLAN tags have been stripped, either
        because they represent proprietary encapsulations, or
        because switch hardware automatically strips the outer VLAN
        encapsulation.
   Reporting extended_vlantunnel information is not a substitute for
   reporting extended_switch information. extended_switch data must
   always be reported to describe the ingress/egress VLAN information
   for the packet. The extended_vlantunnel information only applies to
   nested VLAN tags, and then only when one or more tags has been
   stripped. */
/* opaque = flow_data; enterprise = 0; format = 1012 */
extended_vlantunnel {
  unsigned int stack<>;  /* List of stripped 802.1Q TPID/TCI layers. Each
                            TPID,TCI pair is represented as a single 32 bit
                            integer. Layers listed from outermost to
                            innermost. */
}

/* Counter Data Types

   Wherever possible, the if_counters block should be included. Media
   specific counters can be included as well. */

/* Generic Interface Counters - see RFC 2233 */
/* opaque = counter_data; enterprise = 0; format = 1 */

struct if_counters {
   unsigned int ifIndex;
   unsigned int ifType;
   unsigned hyper ifSpeed;
   unsigned int ifDirection;    /* derived from MAU MIB (RFC 2668)
                                   0 = unkown, 1=full-duplex, 2=half-duplex,
                                   3 = in, 4=out */
   unsigned int ifStatus;       /* bit field with the following bits assigned
                                   bit 0 = ifAdminStatus (0 = down, 1 = up)
                                   bit 1 = ifOperStatus (0 = down, 1 = up) */
   unsigned hyper ifInOctets;
   unsigned int ifInUcastPkts;
   unsigned int ifInMulticastPkts;
   unsigned int ifInBroadcastPkts;
   unsigned int ifInDiscards;
   unsigned int ifInErrors;
   unsigned int ifInUnknownProtos;
   unsigned hyper ifOutOctets;
   unsigned int ifOutUcastPkts;
   unsigned int ifOutMulticastPkts;
   unsigned int ifOutBroadcastPkts;
   unsigned int ifOutDiscards;
   unsigned int ifOutErrors;
   unsigned int ifPromiscuousMode;
}

/* Ethernet Interface Counters - see RFC 2358 */
/* opaque = counter_data; enterprise = 0; format = 2 */

struct ethernet_counters {
   unsigned int dot3StatsAlignmentErrors;
   unsigned int dot3StatsFCSErrors;
   unsigned int dot3StatsSingleCollisionFrames;
   unsigned int dot3StatsMultipleCollisionFrames;
   unsigned int dot3StatsSQETestErrors;
   unsigned int dot3StatsDeferredTransmissions;
   unsigned int dot3StatsLateCollisions;
   unsigned int dot3StatsExcessiveCollisions;
   unsigned int dot3StatsInternalMacTransmitErrors;
   unsigned int dot3StatsCarrierSenseErrors;
   unsigned int dot3StatsFrameTooLongs;
   unsigned int dot3StatsInternalMacReceiveErrors;
   unsigned int dot3StatsSymbolErrors;
}

/* Token Ring Counters - see RFC 1748 */
/* opaque = counter_data; enterprise = 0; format = 3 */

struct tokenring_counters {
  unsigned int dot5StatsLineErrors;
  unsigned int dot5StatsBurstErrors;
  unsigned int dot5StatsACErrors;
  unsigned int dot5StatsAbortTransErrors;
  unsigned int dot5StatsInternalErrors;
  unsigned int dot5StatsLostFrameErrors;
  unsigned int dot5StatsReceiveCongestions;
  unsigned int dot5StatsFrameCopiedErrors;
  unsigned int dot5StatsTokenErrors;
  unsigned int dot5StatsSoftErrors;
  unsigned int dot5StatsHardErrors;
  unsigned int dot5StatsSignalLoss;
  unsigned int dot5StatsTransmitBeacons;
  unsigned int dot5StatsRecoverys;
  unsigned int dot5StatsLobeWires;
  unsigned int dot5StatsRemoves;
  unsigned int dot5StatsSingles;
  unsigned int dot5StatsFreqErrors;
}

/* 100 BaseVG interface counters - see RFC 2020 */
/* opaque = counter_data; enterprise = 0; format = 4 */

struct vg_counters {
  unsigned int dot12InHighPriorityFrames;
  unsigned hyper dot12InHighPriorityOctets;
  unsigned int dot12InNormPriorityFrames;
  unsigned hyper dot12InNormPriorityOctets;
  unsigned int dot12InIPMErrors;
  unsigned int dot12InOversizeFrameErrors;
  unsigned int dot12InDataErrors;
  unsigned int dot12InNullAddressedFrames;
  unsigned int dot12OutHighPriorityFrames;
  unsigned hyper dot12OutHighPriorityOctets;
  unsigned int dot12TransitionIntoTrainings;
  unsigned hyper dot12HCInHighPriorityOctets;
  unsigned hyper dot12HCInNormPriorityOctets;
  unsigned hyper dot12HCOutHighPriorityOctets;
}

/* VLAN Counters */
/* opaque = counter_data; enterprise = 0; format = 5 */

struct vlan_counters {
  unsigned int vlan_id;
  unsigned hyper octets;
  unsigned int ucastPkts;
  unsigned int multicastPkts;
  unsigned int broadcastPkts;
  unsigned int discards;
}

/* Percentage expressed in hundredths of a percent
   (e.g. 100 = 1%). If a percentage value is unknown then
   use the value -1. */

typedef int percentage;

/* Processor Information */
/* opaque = counter_data; enterprise = 0; format = 1001 */

struct processor {
   percentage 5s_cpu;          /* 5 second average CPU utilization */
   percentage 1m_cpu;          /* 1 minute average CPU utilization */
   percentage 5m_cpu;          /* 5 minute average CPU utilization */
   unsigned hyper total_memory /* total memory (in bytes) */
   unsigned hyper free_memory  /* free memory (in bytes) */
}

   The sFlow Datagram and data record specifications make use of
   definitions from a number of existing RFCs [22], [23], [24], [25],
   [26], [27], [28], [29], [30] and [31].
