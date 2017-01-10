use v6;

use Inline::Perl5;
use Convert::ASN1:from<Perl5>;

use Net::LDAP::Filter;
use Net::LDAP::Constant
    :LDAP_SUCCESS
    :LDAP_OPERATIONS_ERROR
    :LDAP_SASL_BIND_IN_PROGRESS
    :LDAP_DECODING_ERROR
    :LDAP_PROTOCOL_ERROR
    :LDAP_ENCODING_ERROR
    :LDAP_FILTER_ERROR
    :LDAP_LOCAL_ERROR
    :LDAP_PARAM_ERROR
    :LDAP_INAPPROPRIATE_AUTH
    :LDAP_SERVER_DOWN
    :LDAP_USER_CANCELED
    :LDAP_EXTENSION_START_TLS
    :LDAP_UNAVAILABLE
;

class Net::LDAP {
    has $.host;
    has $.port;
    has $.socket;
    has $.arg;
    has $.obj;
    has $.ldap-version = 3;
    has $.auth-type = 'simple';
    has $.message-count = 0;

    method new(:$host!, Int :$port = 389) {
        my $socket = connect-ldap(:$host, :$port);
        self.bless(:$host, :$port, :$socket);
    }

    method search($filter) {
        my $messageID = $!message-count++;
        my $ldap-filter = Net::LDAP::Filter.new;

        say "Parsing filter...";
        my $parsed-filter = $ldap-filter.parse($filter);
        say $parsed-filter;

        my %searchRequest =
            baseObject   => 'dc=example,dc=com',
            scope        => 2,
            derefAliases => 2,
            sizeLimit    => 0,
            timeLimit    => 0,
            typesOnly    => 0,
            filter       => $parsed-filter,
            attributes   => [],
        ;

        my %request =
            searchRequest => %searchRequest,
            # controls      => Any,
            messageID       => $messageID;
        ;

        say "";
        # say %request;
        # say %searchRequest<filter><or>[0]<equalityMatch><assertionValue>;
        # %searchRequest<filter><or>[0]<equalityMatch><assertionValue>;

        say %request.perl;

        say "";
        say %searchRequest<filter><or>[0]<equalityMatch><assertionValue>;
        say "";

        my $pdu = encode %request;

        say "pdu => ", $pdu;

        my $response = send-message :$pdu, :socket($!socket);
        my %result = decode(:pdu($response));

        dd %result;

    }

    method bind(:$dn!, :$password) {
        my $messageID = $!message-count++;
        my %request =
            bindRequest => {
                authentication => { simple => $password },
                name => $dn,
                version => $!ldap-version,
            },
            messageID => $messageID,
        ;

        my $pdu = encode %request;
        my $response = send-message :$pdu, :socket($!socket);
        my %result = decode(:pdu($response));

        return process-result :%result;
    }

    my sub process-result(:%result) {
        my $messageID = %result<messageID>;
        my %status = %result<protocolOp><bindResponse>;

        return {
            resultCode => %status<resultCode>,
            matchedDn  => %status<matchedDN>,
            errorMessage => %status<errorMessage>,
        }
    }

    my sub decode(:$pdu) {
        my $asn = Convert::ASN1.new;
        $asn.prepare(get-prepared);
        my $qsn = $asn.find('LDAPResponse');
        die "Error => ", $qsn.serror if $qsn.error;
        my $decoded = $qsn.decode($pdu);
    }

    my sub encode(%bind-request) {
        my $asn = Convert::ASN1.new;
        $asn.prepare(get-prepared);
        my $bsn = $asn.find('LDAPRequest');
        die "Error => ", $bsn.error if $bsn.error;

        my $pdu = $bsn.encode(%bind-request);
        die "Error => ", $bsn.error if $bsn.error;
        return $pdu;
    }

    my sub send-message(:$pdu, :$socket) {
        $socket.write($pdu);
        my $response = $socket.recv(:bin);
        return $response;
    }

    my sub connect-ldap(:$host, :$port) {
        IO::Socket::INET.new(
            :$host,
            :$port,
        );
    }
}

my sub get-prepared {
    return q"
        -- We have split LDAPMessage into LDAPResponse and LDAPRequest
        -- The purpose of this is two fold
        -- 1) for encode we don't want the protocolOp
        --    in the hierarchy as it is not really needed
        -- 2) For decode we do want it, this allows Net::LDAP::Message::decode
        --    to be much simpler. Decode will also be faster due to
        --    less elements in the CHOICE

        LDAPRequest ::= SEQUENCE {
        messageID       MessageID,
        -- protocolOp
        CHOICE {
            bindRequest     BindRequest,
            unbindRequest   UnbindRequest,
            searchRequest   SearchRequest,
            modifyRequest   ModifyRequest,
            addRequest      AddRequest,
            delRequest      DelRequest,
            modDNRequest    ModifyDNRequest,
            compareRequest  CompareRequest,
            abandonRequest  AbandonRequest,
            extendedReq     ExtendedRequest }
        controls        [0] Controls OPTIONAL }

        LDAPResponse ::= SEQUENCE {
        messageID       MessageID,
        protocolOp      CHOICE {
            bindResponse    BindResponse,
            searchResEntry  SearchResultEntry,
            searchResDone   SearchResultDone,
            searchResRef    SearchResultReference,
            modifyResponse  ModifyResponse,
            addResponse     AddResponse,
            delResponse     DelResponse,
            modDNResponse   ModifyDNResponse,
            compareResponse CompareResponse,
            extendedResp    ExtendedResponse,
            intermediateResponse IntermediateResponse }
        controls        [0] Controls OPTIONAL }

        MessageID ::= INTEGER -- (0 .. maxInt)

        -- maxInt INTEGER ::= 2147483647 -- (2^^31 - 1) --

        LDAPString ::= OCTET STRING -- UTF-8 encoded, [ISO10646] characters

        LDAPOID ::= OCTET STRING -- Constrained to <numericoid> [RFC4512]

        LDAPDN ::= LDAPString -- Constrained to <distinguishedName> [RFC4514]

        RelativeLDAPDN ::= LDAPString -- Constrained to <name-component> [RFC4514]

        AttributeDescription ::= LDAPString -- Constrained to <attributedescription> [RFC4512]

        AttributeValue ::= OCTET STRING

        AttributeValueAssertion ::= SEQUENCE {
        attributeDesc   AttributeDescription,
        assertionValue  AssertionValue }

        AssertionValue ::= OCTET STRING

        PartialAttribute ::= SEQUENCE {
        type    AttributeDescription,
        vals    SET OF AttributeValue }

        Attribute ::= PartialAttribute -- (WITH COMPONENTS { ..., vals (SIZE(1..MAX))})

        MatchingRuleId ::= LDAPString

        LDAPResult ::= SEQUENCE {
        resultCode      ENUMERATED {
            success                      (0),
            operationsError              (1),
            protocolError                (2),
            timeLimitExceeded            (3),
            sizeLimitExceeded            (4),
            compareFalse                 (5),
            compareTrue                  (6),
            authMethodNotSupported       (7),
            strongAuthRequired           (8),
            -- 9 reserved --
            referral                     (10),
            adminLimitExceeded           (11),
            unavailableCriticalExtension (12),
            confidentialityRequired      (13),
            saslBindInProgress           (14),
            noSuchAttribute              (16),
            undefinedAttributeType       (17),
            inappropriateMatching        (18),
            constraintViolation          (19),
            attributeOrValueExists       (20),
            invalidAttributeSyntax       (21),
            -- 22-31 unused --
            noSuchObject                 (32),
            aliasProblem                 (33),
            invalidDNSyntax              (34),
            -- 35 reserved for undefined isLeaf --
            aliasDereferencingProblem    (36),
            -- 37-47 unused --
            inappropriateAuthentication  (48),
            invalidCredentials           (49),
            insufficientAccessRights     (50),
            busy                         (51),
            unavailable                  (52),
            unwillingToPerform           (53),
            loopDetect                   (54),
            -- 55-63 unused --
            namingViolation              (64),
            objectClassViolation         (65),
            notAllowedOnNonLeaf          (66),
            notAllowedOnRDN              (67),
            entryAlreadyExists           (68),
            objectClassModsProhibited    (69),
            -- 70 reserved for CLDAP --
            affectsMultipleDSAs          (71),
            -- 72-79 unused --
            other                        (80)}
            -- 81-90 reserved for APIs --
        matchedDN       LDAPDN,
        errorMessage    LDAPString,
        referral        [3] Referral OPTIONAL }

        Referral ::= SEQUENCE OF URI

        URI ::= LDAPString -- limited to characters permitted in URIs

        Controls ::= SEQUENCE OF Control

        -- Names changed here for backwards compat with previous
        -- Net::LDAP    --GMB
        Control ::= SEQUENCE {
        type            LDAPOID,                       -- controlType
        critical        BOOLEAN OPTIONAL, -- DEFAULT FALSE,    -- criticality
        value           OCTET STRING OPTIONAL }        -- controlValue

        BindRequest ::= [APPLICATION 0] SEQUENCE {
        version         INTEGER, -- (1 .. 127),
        name            LDAPDN,
        authentication  AuthenticationChoice }

        AuthenticationChoice ::= CHOICE {
        simple          [0] OCTET STRING,
                -- 1 and 2 reserved
        sasl            [3] SaslCredentials }

        SaslCredentials ::= SEQUENCE {
        mechanism       LDAPString,
        credentials     OCTET STRING OPTIONAL }

        BindResponse ::= [APPLICATION 1] SEQUENCE {
        COMPONENTS OF LDAPResult,
        serverSaslCreds    [7] OCTET STRING OPTIONAL }

        UnbindRequest ::= [APPLICATION 2] NULL

        SearchRequest ::= [APPLICATION 3] SEQUENCE {
        baseObject      LDAPDN,
        scope           ENUMERATED {
            baseObject              (0),
            singleLevel             (1),
            wholeSubtree            (2),
            subOrdinates            (3) } -- OpenLDAP extension
        derefAliases    ENUMERATED {
            neverDerefAliases       (0),
            derefInSearching        (1),
            derefFindingBaseObj     (2),
            derefAlways             (3) }
        sizeLimit       INTEGER, -- (0 .. maxInt),
        timeLimit       INTEGER, -- (0 .. maxInt),
        typesOnly       BOOLEAN,
        filter          Filter,
        attributes      AttributeSelection }

        AttributeSelection ::= SEQUENCE OF LDAPString
            -- The LDAPString is constrained to <attributeSelector> [RFC 4511]

        Filter ::= CHOICE {
        and             [0] SET OF Filter,
        or              [1] SET OF Filter,
        not             [2] Filter,
        equalityMatch   [3] AttributeValueAssertion,
        substrings      [4] SubstringFilter,
        greaterOrEqual  [5] AttributeValueAssertion,
        lessOrEqual     [6] AttributeValueAssertion,
        present         [7] AttributeDescription,
        approxMatch     [8] AttributeValueAssertion,
        extensibleMatch [9] MatchingRuleAssertion }

        SubstringFilter ::= SEQUENCE {
        type            AttributeDescription,
        -- at least one must be present
        substrings      SEQUENCE OF CHOICE {
            initial [0] AssertionValue,    -- can occur at most once
            any     [1] AssertionValue,
            final   [2] AssertionValue } } -- can occur at most once

        MatchingRuleAssertion ::= SEQUENCE {
        matchingRule    [1] MatchingRuleId OPTIONAL,
        type            [2] AttributeDescription OPTIONAL,
        matchValue      [3] AssertionValue,
        dnAttributes    [4] BOOLEAN OPTIONAL } -- DEFAULT FALSE }

        SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
        objectName      LDAPDN,
        attributes      PartialAttributeList }

        PartialAttributeList ::= SEQUENCE OF PartialAttribute

        SearchResultReference ::= [APPLICATION 19] SEQUENCE OF URI

        SearchResultDone ::= [APPLICATION 5] LDAPResult

        ModifyRequest ::= [APPLICATION 6] SEQUENCE {
        object          LDAPDN,
        modification    SEQUENCE OF SEQUENCE {
            operation       ENUMERATED {
                add     (0),
                delete  (1),
                replace (2),
                increment (3) } -- increment from RFC 4525
            modification    PartialAttribute } }

        ModifyResponse ::= [APPLICATION 7] LDAPResult

        AddRequest ::= [APPLICATION 8] SEQUENCE {
        objectName      LDAPDN,
        attributes      AttributeList }

        AttributeList ::= SEQUENCE OF Attribute

        AddResponse ::= [APPLICATION 9] LDAPResult

        DelRequest ::= [APPLICATION 10] LDAPDN

        DelResponse ::= [APPLICATION 11] LDAPResult

        ModifyDNRequest ::= [APPLICATION 12] SEQUENCE {
        entry           LDAPDN,
        newrdn          RelativeLDAPDN,
        deleteoldrdn    BOOLEAN,
        newSuperior     [0] LDAPDN OPTIONAL }

        ModifyDNResponse ::= [APPLICATION 13] LDAPResult

        CompareRequest ::= [APPLICATION 14] SEQUENCE {
        entry           LDAPDN,
        ava             AttributeValueAssertion }

        CompareResponse ::= [APPLICATION 15] LDAPResult

        AbandonRequest ::= [APPLICATION 16] MessageID

        ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
        requestName     [0] LDAPOID,
        requestValue    [1] OCTET STRING OPTIONAL }

        ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
        COMPONENTS OF LDAPResult,
        responseName    [10] LDAPOID OPTIONAL,
        responseValue   [11] OCTET STRING OPTIONAL }

        IntermediateResponse ::= [APPLICATION 25] SEQUENCE {
        responseName    [0] LDAPOID OPTIONAL,
        responseValue   [1] OCTET STRING OPTIONAL }


        -- Virtual List View Control
        VirtualListViewRequest ::= SEQUENCE {
        beforeCount     INTEGER, --(0 .. maxInt),
        afterCount      INTEGER, --(0 .. maxInt),
        CHOICE {
            byoffset [0] SEQUENCE {
            offset          INTEGER,  --(0 .. maxInt),
            contentCount    INTEGER } --(0 .. maxInt) }
            byValue [1] AssertionValue }
            -- byValue [1] greaterThanOrEqual assertionValue }
        contextID     OCTET STRING OPTIONAL }

        VirtualListViewResponse ::= SEQUENCE {
        targetPosition    INTEGER, --(0 .. maxInt),
        contentCount      INTEGER, --(0 .. maxInt),
        virtualListViewResult ENUMERATED {
            success                   (0),
            operatonsError            (1),
            unwillingToPerform       (53),
            insufficientAccessRights (50),
            busy                     (51),
            timeLimitExceeded         (3),
            adminLimitExceeded       (11),
            sortControlMissing       (60),
            indexRangeError          (61),
            other                    (80) }
        contextID     OCTET STRING OPTIONAL     }


        LDAPEntry ::= COMPONENTS OF AddRequest

        -- RFC-2891 Server Side Sorting Control
        -- Current parser does not allow a named entity following the ::=
        -- so we use a COMPONENTS OF hack
        SortRequestDummy ::= SEQUENCE {
        order SEQUENCE OF SEQUENCE {
            type         OCTET STRING,
            orderingRule [0] OCTET STRING OPTIONAL,
            reverseOrder [1] BOOLEAN OPTIONAL } }

        SortRequest ::= COMPONENTS OF SortRequestDummy

        SortResult ::= SEQUENCE {
        sortResult  ENUMERATED {
            success                   (0), -- results are sorted
            operationsError           (1), -- server internal failure
            timeLimitExceeded         (3), -- timelimit reached before
                        -- sorting was completed
            strongAuthRequired        (8), -- refused to return sorted
                        -- results via insecure
                        -- protocol
            adminLimitExceeded       (11), -- too many matching entries
                        -- for the server to sort
            noSuchAttribute          (16), -- unrecognized attribute
                        -- type in sort key
            inappropriateMatching    (18), -- unrecognized or inappro-
                        -- priate matching rule in
                        -- sort key
            insufficientAccessRights (50), -- refused to return sorted
                        -- results to this client
            busy                     (51), -- too busy to process
            unwillingToPerform       (53), -- unable to sort
            other                    (80) }
        attributeType [0] AttributeDescription OPTIONAL }

        -- RFC-2696 Paged Results Control
        realSearchControlValue ::= SEQUENCE {
        size            INTEGER, --  (0..maxInt),
                -- requested page size from client
                -- result set size estimate from server
        cookie          OCTET STRING }

        -- draft-behera-ldap-password-policy-09
        ppControlResponse ::= SEQUENCE {
        warning [0] PPWarning OPTIONAL,
        error   [1] PPError OPTIONAL
        }
        PPWarning ::= CHOICE {
            timeBeforeExpiration [0] INTEGER, -- (0..maxInt),
            graceAuthNsRemaining [1] INTEGER -- (0..maxInt)
        }
        PPError ::= ENUMERATED {
            passwordExpired             (0),
            accountLocked               (1),
            changeAfterReset            (2),
            passwordModNotAllowed       (3),
            mustSupplyOldPassword       (4),
            insufficientPasswordQuality (5),
            passwordTooShort            (6),
            passwordTooYoung            (7),
            passwordInHistory           (8)
        }

        -- RFC-4370 Proxied Authorization Control
        proxyAuthValue ::= SEQUENCE {
        proxyDN LDAPDN
        }

        -- RFC-3296 ManageDsaIT Control
        ManageDsaIT ::= SEQUENCE {
        dummy INTEGER OPTIONAL   -- it really is unused
        }

        -- Persistent Search Control
        PersistentSearch ::= SEQUENCE {
        changeTypes INTEGER,
        changesOnly BOOLEAN,
        returnECs   BOOLEAN
        }

        -- Entry Change Notification Control
        EntryChangeNotification ::= SEQUENCE {
        changeType ENUMERATED {
            add         (1),
            delete      (2),
            modify      (4),
            modDN       (8)
        }
        previousDN   LDAPDN OPTIONAL,     -- modifyDN ops. only
        changeNumber INTEGER OPTIONAL     -- if supported
        }

        -- RFC-3876 Matched Values Control
        ValuesReturnFilter ::= SEQUENCE OF SimpleFilterItem

        SimpleFilterItem ::= CHOICE {
        equalityMatch   [3] AttributeValueAssertion,
        substrings      [4] SubstringFilter,
        greaterOrEqual  [5] AttributeValueAssertion,
        lessOrEqual     [6] AttributeValueAssertion,
        present         [7] AttributeDescription,
        approxMatch     [8] AttributeValueAssertion,
        extensibleMatch [9] SimpleMatchingAssertion }

        SimpleMatchingAssertion ::= SEQUENCE {
        matchingRule    [1] MatchingRuleId OPTIONAL,
        type            [2] AttributeDescription OPTIONAL,
        --- at least one of the above must be present
        matchValue      [3] AssertionValue }

        -- RFC-4533 LDAP Content Synchronization Operation

        syncUUID ::= OCTET STRING -- (SIZE(16))

        syncCookie ::= OCTET STRING

        syncRequestValue ::= SEQUENCE {
        mode ENUMERATED {
            -- 0 unused
            refreshOnly       (1),
            -- 2 reserved
            refreshAndPersist (3)
        }
        cookie     syncCookie OPTIONAL,
        reloadHint BOOLEAN OPTIONAL -- DEFAULT FALSE
        }

        syncStateValue ::= SEQUENCE {
        state ENUMERATED {
            present (0),
            add     (1),
            modify  (2),
            delete  (3)
        }
        entryUUID syncUUID,
        cookie    syncCookie OPTIONAL
        }

        syncDoneValue ::= SEQUENCE {
        cookie          syncCookie OPTIONAL,
        refreshDeletes  BOOLEAN OPTIONAL -- DEFAULT FALSE
        }

        syncInfoValue ::= CHOICE {
        newcookie      [0] syncCookie,
        refreshDelete  [1] SEQUENCE {
            cookie         syncCookie OPTIONAL,
            refreshDone    BOOLEAN OPTIONAL -- DEFAULT TRUE
        }
        refreshPresent [2] SEQUENCE {
            cookie         syncCookie OPTIONAL,
            refreshDone    BOOLEAN OPTIONAL -- DEFAULT TRUE
        }
        syncIdSet      [3] SEQUENCE {
            cookie         syncCookie OPTIONAL,
            refreshDeletes BOOLEAN OPTIONAL, -- DEFAULT FALSE
            syncUUIDs      SET OF syncUUID
        }
        }
    ";
}

# =begin foo

# 
# # TODO (Doug): Check for IPv6 support. Currently sets to yes and just fails if the system can't
#     constant CAN_IPV6 = True;
#     my $ldap_version = 3; # Default LDAP protocol
# 
#     my sub _options(%ret) {
#         my $once = 0;
#         for %ret.keys.grep(*.starts-with('-')) -> $v {
#             $once++ or note 'deprecated use of leading - for options';
#             %ret{ $v.substr(1) } = %ret{ $v };
#         }
# 
#         # TODO (Doug): This might not be working as intended
#         # %ret<control> must be an array
#         if %ret<control>:exists {
#             %ret<control> = %ret<control>.map({ $_ });
#             warn 'Doing stuff wrong probably';
#             # TODO (Doug): No idea what this would do
#             # %ret<control> = %ret<control>.map({ $_.to_asn });
#          }
# 
#         return %ret;
#     }
# 
#     my sub _dn_options(@options) {
#         unshift @options, 'dn'  if @options.elems == 0;
#         my %options = @options;
#         _options(%options);
#     }
# 
#     my sub _err_msg($mesg) {
#         my $errstr = $mesg.dn || '';
#         $errstr ~= ': '  if $errstr;
#         $errstr ~ $mesg.error;
#     }
# 
#     my %onerror = (
#         die   => sub (@errors) {  die(_err_msg(@errors)) },
#         warn  => sub (@errors) { warn(_err_msg(@errors)) },
#         undef => sub (@errors) { note(_err_msg(@errors)) },
#     );
# 
#     my sub _error($ldap, $mesg, *@rest) {
#         $mesg.set_error(@rest);
#         $ldap<net_ldap_onerror> && !$ldap<net_ldap_async>
#             ?? $ldap<net_ldap_onerror>($mesg)
#             !! $mesg;
#     }
# 
#     method new (:$host, *%options) {
#         my $arg  = _options(|%options);
#         # TODO (Doug): Figure out what this does?
#         my $obj;
#         # my $obj  = bless {}, $type;
# 
#         # TODO (Doug): Support single and multiple hosts
#         for ([$host]) -> $uri {
#             my $scheme = $arg.<scheme> || 'ldap';
#             my $h = $uri;
# 
#             if (defined($h)) {
#                 # TODO (Doug): Perl6 regex these
#                 # $h ~~ s,^(\w+)://,, and $scheme = lc($0);
#                 # $h ~~ s,/.*,,; # remove path part
#                 # $h ~~ s/%([A-Fa-f0-9]{2})/chr(hex($1))/eg; # unescape
#             }
# 
#             my $meth = $obj.can("connect_$scheme") or next;
#                 if (&$meth($obj, $h, $arg)) {
#                 $obj<net_ldap_uri>    = $uri;
#                 $obj<net_ldap_scheme> = $scheme;
#                 last;
#             }
#         }
# 
#         return unless $obj<net_ldap_socket>;
# 
#         # $obj<net_ldap_socket>.setsockopt(SOL_SOCKET, SO_KEEPALIVE, $arg<keepalive> ?? 1 :: 0)
#         #     if (defined($arg<keepalive>));
# 
#         $obj<net_ldap_rawsocket> = $obj<net_ldap_socket>;
#         $obj<net_ldap_resp>    = {};
#         $obj<net_ldap_version> = $arg<version> || $ldap_version;
#         $obj<net_ldap_async>   = $arg<async> ?? 1 !! 0;
#         $obj<raw> = $arg<raw>  if $arg<raw>;
# 
#         my $onerr;
#         if (defined($onerr = $arg<onerror>)) {
#             $onerr = %onerror{$onerr}  if %onerror{$onerr}:exists;
#             $obj<net_ldap_onerror> = $onerr;
#         }
# 
#         $obj.debug($arg<debug> || 0 );
# 
#         $obj.outer;
#     }
# }
# 
# =end foo
# 
# =begin ldap
# 
#     sub connect_ldap {
#         my ($ldap, $host, $arg) = @_;
#         my $port = $arg->{port} || 389;
#         my $class = (CAN_IPV6) ? CAN_IPV6 : 'IO::Socket::INET';
#         my $domain = $arg->{inet4} ? AF_INET : ($arg->{inet6} ? AF_INET6 : AF_UNSPEC);
# 
#         # separate port from host overwriting given/default port
#         $host =~ s/^([^:]+|\[.*\]):(\d+)$/$1/ and $port = $2;
# 
#         if ($arg->{inet6} && !CAN_IPV6) {
#             $@ = 'unable to load IO::Socket::INET6; no IPv6 support';
#             return undef;
#         }
# 
#         $ldap->{net_ldap_socket} = $class->new(
#             PeerAddr   => $host,
#             PeerPort   => $port,
#             LocalAddr  => $arg->{localaddr} || undef,
#             Proto      => 'tcp',
#             Domain     => $domain,
#             MultiHomed => $arg->{multihomed},
#             Timeout    => defined $arg->{timeout}
#                 ? $arg->{timeout}
#                 : 120
#         ) or return undef;
# 
#         $ldap->{net_ldap_host} = $host;
#         $ldap->{net_ldap_port} = $port;
#         }
# }
# 
# =end ldap
# 
# 
# =begin old
# 
# # use Tie::Hash;
# # use Convert::ASN1 qw(asn_read);
# # use Net::LDAP::Message;
# # use Net::LDAP::ASN qw(LDAPResponse);
# 
# # check for IPv6 support: prefer IO::Socket::IP 0.20+ over IO::Socket::INET6
# use constant CAN_IPV6 => do {
#                            local $SIG{__DIE__};
# 
#                            eval { require IO::Socket::IP; IO::Socket::IP->VERSION(0.20); }
#                            ? 'IO::Socket::IP'
#                            : eval { require IO::Socket::INET6; }
#                              ? 'IO::Socket::INET6'
#                              : '';
#                          };
# 
# our $VERSION 	= '0.65';
# our @ISA     	= qw(Tie::StdHash Net::LDAP::Extra);
# our $LDAP_VERSION 	= 3;      # default LDAP protocol version
# 
# # Net::LDAP::Extra will only exist is someone use's the module. But we need
# # to ensure the package stash exists or perl will complain that we inherit
# # from a non-existent package. I could just use the module, but I did not
# # want to.
# 
# $Net::LDAP::Extra::create = $Net::LDAP::Extra::create = 0;
# 
# sub import {
#     shift;
#     unshift @_, 'Net::LDAP::Constant';
#     require Net::LDAP::Constant;
#     goto &{Net::LDAP::Constant->can('import')};
# }
# 
# sub _options {
#   my %ret = @_;
#   my $once = 0;
#   for my $v (grep { /^-/ } keys %ret) {
#     require Carp;
#     $once++  or Carp::carp('deprecated use of leading - for options');
#     $ret{substr($v, 1)} = $ret{$v};
#   }
# 
#   $ret{control} = [ map { (ref($_) =~ /[^A-Z]/) ? $_->to_asn : $_ }
# 		      ref($ret{control}) eq 'ARRAY'
# 			? @{$ret{control}}
# 			: $ret{control}
#                   ]
#     if exists $ret{control};
# 
#   \%ret;
# }
# 
# sub _dn_options {
#   unshift @_, 'dn'  if @_ & 1;
#   &_options;
# }
# 
# sub _err_msg {
#   my $mesg = shift;
#   my $errstr = $mesg->dn || '';
#   $errstr .= ': '  if $errstr;
#   $errstr . $mesg->error;
# }
# 
# my %onerror = (
#   die   => sub { require Carp; Carp::croak(_err_msg(@_)) },
#   warn  => sub { require Carp; Carp::carp(_err_msg(@_)); $_[0] },
#   undef => sub { require Carp; Carp::carp(_err_msg(@_))  if $^W; undef },
# );
# 
# sub _error {
#   my ($ldap, $mesg) = splice(@_, 0, 2);
# 
#   $mesg->set_error(@_);
#   $ldap->{net_ldap_onerror} && !$ldap->{net_ldap_async}
#     ? scalar &{$ldap->{net_ldap_onerror}}($mesg)
#     : $mesg;
# }
# 
# sub new {
#   my $self = shift;
#   my $type = ref($self) || $self;
#   my $host = shift  if @_ % 2;
#   my $arg  = &_options;
#   my $obj  = bless {}, $type;
# 
#   foreach my $uri (ref($host) ? @$host : ($host)) {
#     my $scheme = $arg->{scheme} || 'ldap';
#     my $h = $uri;
#     if (defined($h)) {
#       $h =~ s,^(\w+)://,, and $scheme = lc($1);
#       $h =~ s,/.*,,; # remove path part
#       $h =~ s/%([A-Fa-f0-9]{2})/chr(hex($1))/eg; # unescape
#     }
#     my $meth = $obj->can("connect_$scheme")  or next;
#     if (&$meth($obj, $h, $arg)) {
#       $obj->{net_ldap_uri} = $uri;
#       $obj->{net_ldap_scheme} = $scheme;
#       last;
#     }
#   }
# 
#   return undef  unless $obj->{net_ldap_socket};
# 
#   $obj->{net_ldap_socket}->setsockopt(SOL_SOCKET, SO_KEEPALIVE, $arg->{keepalive} ? 1 : 0)
#     if (defined($arg->{keepalive}));
# 
#   $obj->{net_ldap_rawsocket} = $obj->{net_ldap_socket};
#   $obj->{net_ldap_resp}    = {};
#   $obj->{net_ldap_version} = $arg->{version} || $LDAP_VERSION;
#   $obj->{net_ldap_async}   = $arg->{async} ? 1 : 0;
#   $obj->{raw} = $arg->{raw}  if ($arg->{raw});
# 
#   if (defined(my $onerr = $arg->{onerror})) {
#     $onerr = $onerror{$onerr}  if exists $onerror{$onerr};
#     $obj->{net_ldap_onerror} = $onerr;
#   }
# 
#   $obj->debug($arg->{debug} || 0 );
# 
#   $obj->outer;
# }
# 
# sub connect_ldap {
#   my ($ldap, $host, $arg) = @_;
#   my $port = $arg->{port} || 389;
#   my $class = (CAN_IPV6) ? CAN_IPV6 : 'IO::Socket::INET';
#   my $domain = $arg->{inet4} ? AF_INET : ($arg->{inet6} ? AF_INET6 : AF_UNSPEC);
# 
#   # separate port from host overwriting given/default port
#   $host =~ s/^([^:]+|\[.*\]):(\d+)$/$1/ and $port = $2;
# 
#   if ($arg->{inet6} && !CAN_IPV6) {
#     $@ = 'unable to load IO::Socket::INET6; no IPv6 support';
#     return undef;
#   }
# 
#   $ldap->{net_ldap_socket} = $class->new(
#     PeerAddr   => $host,
#     PeerPort   => $port,
#     LocalAddr  => $arg->{localaddr} || undef,
#     Proto      => 'tcp',
#     Domain     => $domain,
#     MultiHomed => $arg->{multihomed},
#     Timeout    => defined $arg->{timeout}
# 		 ? $arg->{timeout}
# 		 : 120
#   ) or return undef;
# 
#   $ldap->{net_ldap_host} = $host;
#   $ldap->{net_ldap_port} = $port;
# }
# 
# 
# # Different OpenSSL verify modes.
# my %ssl_verify = qw(none 0 optional 1 require 3);
# 
# sub connect_ldaps {
#   my ($ldap, $host, $arg) = @_;
#   my $port = $arg->{port} || 636;
#   my $domain = $arg->{inet4} ? AF_INET : ($arg->{inet6} ? AF_INET6 : AF_UNSPEC);
# 
#   if ($arg->{inet6} && !CAN_IPV6) {
#     $@ = 'unable to load IO::Socket::INET6; no IPv6 support';
#     return undef;
#   }
# 
#   require IO::Socket::SSL;
# 
#   # separate port from host overwriting given/default port
#   $host =~ s/^([^:]+|\[.*\]):(\d+)$/$1/ and $port = $2;
# 
#   $arg->{sslserver} = $host  unless defined $arg->{sslserver};
# 
#   $ldap->{net_ldap_socket} = IO::Socket::SSL->new(
#     PeerAddr 	    => $host,
#     PeerPort 	    => $port,
#     LocalAddr       => $arg->{localaddr} || undef,
#     Proto    	    => 'tcp',
#     Domain          => $domain,
#     Timeout  	    => defined $arg->{timeout} ? $arg->{timeout} : 120,
#     _SSL_context_init_args($arg)
#   ) or return undef;
# 
#   $ldap->{net_ldap_host} = $host;
#   $ldap->{net_ldap_port} = $port;
# }
# 
# sub _SSL_context_init_args {
#   my $arg = shift;
# 
#   my $verify = 0;
#   my %verifycn_ctx = ();
#   my ($clientcert, $clientkey, $passwdcb);
# 
#   if (exists $arg->{verify}) {
#       my $v = lc $arg->{verify};
#       $verify = 0 + (exists $ssl_verify{$v} ? $ssl_verify{$v} : $verify);
# 
#       if ($verify) {
#         $verifycn_ctx{SSL_verifycn_scheme} = 'ldap';
#         $verifycn_ctx{SSL_verifycn_name} = $arg->{sslserver}
#           if (defined $arg->{sslserver});
#       }
#   }
# 
#   if (exists $arg->{clientcert}) {
#       $clientcert = $arg->{clientcert};
#       if (exists $arg->{clientkey}) {
# 	  $clientkey = $arg->{clientkey};
#       } else {
# 	  require Carp;
# 	  Carp::croak('Setting client public key but not client private key');
#       }
#   }
# 
#   if ($arg->{checkcrl} && !$arg->{capath}) {
#       require Carp;
#       Carp::croak('Cannot check CRL without having CA certificates');
#   }
# 
#   if (exists $arg->{keydecrypt}) {
#       $passwdcb = $arg->{keydecrypt};
#   }
# 
#   # allow deprecated "sslv2/3" in addition to IO::Socket::SSL's "sslv23"
#   if (defined $arg->{sslversion}) {
#       $arg->{sslversion} =~ s:sslv2/3:sslv23:io;
#   }
# 
#   (
#     defined $arg->{ciphers} ?
#       ( SSL_cipher_list => $arg->{ciphers} ) : (),
#     defined $arg->{sslversion} ?
#       ( SSL_version     => $arg->{sslversion} ) : (),
#     SSL_ca_file         => exists  $arg->{cafile}  ? $arg->{cafile}  : '',
#     SSL_ca_path         => exists  $arg->{capath}  ? $arg->{capath}  : '',
#     SSL_key_file        => $clientcert ? $clientkey : undef,
#     SSL_passwd_cb       => $passwdcb,
#     SSL_check_crl       => $arg->{checkcrl} ? 1 : 0,
#     SSL_use_cert        => $clientcert ? 1 : 0,
#     SSL_cert_file       => $clientcert,
#     SSL_verify_mode     => $verify,
#     %verifycn_ctx,
#   );
# }
# 
# sub connect_ldapi {
#   my ($ldap, $peer, $arg) = @_;
# 
#   $peer = $ENV{LDAPI_SOCK} || '/var/run/ldapi'
#     unless length $peer;
# 
#   require IO::Socket::UNIX;
# 
#   $ldap->{net_ldap_socket} = IO::Socket::UNIX->new(
#     Peer => $peer,
#     Timeout  => defined $arg->{timeout}
# 		 ? $arg->{timeout}
# 		 : 120
#   ) or return undef;
# 
#   # try to get canonical host name [to allow start_tls on the connection]
#   require Socket;
#   if (Socket->can('getnameinfo') && Socket->can('getaddrinfo')) {
#     my @addrs;
#     my ($err, $host, $path) = Socket::getnameinfo($ldap->{net_ldap_socket}->peername, &Socket::AI_CANONNAME);
# 
#     ($err, @addrs) = Socket::getaddrinfo($host, 0, { flags => &Socket::AI_CANONNAME } )
#       unless ($err);
#     map { $ldap->{net_ldap_host} = $_->{canonname}  if ($_->{canonname}) }  @addrs
#       unless ($err);
#   }
# 
#   $ldap->{net_ldap_host} ||= 'localhost';
#   $ldap->{net_ldap_peer} = $peer;
# }
# 
# sub message {
#   my $ldap = shift;
#   shift->new($ldap, @_);
# }
# 
# sub async {
#   my $ldap = shift;
# 
#   @_
#     ? ($ldap->{net_ldap_async}, $ldap->{net_ldap_async} = shift)[0]
#     : $ldap->{net_ldap_async};
# }
# 
# sub debug {
#   my $ldap = shift;
# 
#   require Convert::ASN1::Debug  if $_[0];
# 
#   @_
#     ? ($ldap->{net_ldap_debug}, $ldap->{net_ldap_debug} = shift)[0]
#     : $ldap->{net_ldap_debug};
# }
# 
# sub sasl {
#   $_[0]->{sasl};
# }
# 
# sub socket {
#   my $ldap = shift;
#   my %opt = @_;
# 
#   (exists($opt{sasl_layer}) && !$opt{sasl_layer})
#     ? $ldap->{net_ldap_rawsocket}
#     : $ldap->{net_ldap_socket};
# }
# 
# sub host {
#   my $ldap = shift;
#   ($ldap->{net_ldap_scheme} ne 'ldapi')
#   ? $ldap->{net_ldap_host}
#   : $ldap->{net_ldap_peer};
# }
# 
# sub port {
#   $_[0]->{net_ldap_port} || undef;
# }
# 
# sub scheme {
#   $_[0]->{net_ldap_scheme};
# }
# 
# sub uri {
#   $_[0]->{net_ldap_uri};
# }
# 
# 
# sub unbind {
#   my $ldap = shift;
#   my $arg  = &_options;
# 
#   my $mesg = $ldap->message('Net::LDAP::Unbind' => $arg);
# 
#   my $control = $arg->{control}
#     and $ldap->{net_ldap_version} < 3
#     and return _error($ldap, $mesg, LDAP_PARAM_ERROR, 'Controls require LDAPv3');
# 
#   $mesg->encode(
#     unbindRequest => 1,
#     controls      => $control,
#   ) or return _error($ldap, $mesg, LDAP_ENCODING_ERROR, "$@");
# 
#   $ldap->_sendmesg($mesg);
# }
# 
# # convenience alias
# *done = \&unbind;
# 
# 
# sub ldapbind {
#   require Carp;
#   Carp::carp('->ldapbind deprecated, use ->bind')  if $^W;
#   goto &bind;
# }
# 
# 
# my %ptype = qw(
#   password        simple
#   krb41password   krbv41
#   krb42password   krbv42
#   kerberos41      krbv41
#   kerberos42      krbv42
#   sasl            sasl
#   noauth          anon
#   anonymous       anon
# );
# 
# sub bind {
#   my $ldap = shift;
#   my $arg  = &_dn_options;
# 
#   require Net::LDAP::Bind;
#   my $mesg = $ldap->message('Net::LDAP::Bind' => $arg);
# 
#   $ldap->version(delete $arg->{version})
#     if exists $arg->{version};
# 
#   my $dn      = delete $arg->{dn} || '';
#   my $control = delete $arg->{control}
#     and $ldap->{net_ldap_version} < 3
#     and return _error($ldap, $mesg, LDAP_PARAM_ERROR, 'Controls require LDAPv3');
# 
#   my %stash = (
#     name    => ref($dn) ? $dn->dn : $dn,
#     version => $ldap->version,
#   );
# 
#   my($auth_type, $passwd) = scalar(keys %$arg) ? () : (simple => '');
# 
#   keys %ptype; # Reset iterator
#   while (my($param, $type) = each %ptype) {
#     if (exists $arg->{$param}) {
#       ($auth_type, $passwd) = $type eq 'anon' ? (simple => '') : ($type, $arg->{$param});
#       return _error($ldap, $mesg, LDAP_INAPPROPRIATE_AUTH, 'No password, did you mean noauth or anonymous ?')
#         if $type eq 'simple' and $passwd eq '';
#       last;
#     }
#   }
# 
#   return _error($ldap, $mesg, LDAP_INAPPROPRIATE_AUTH, 'No AUTH supplied')
#     unless $auth_type;
# 
#   if ($auth_type eq 'sasl') {
# 
#     return _error($ldap, $mesg, LDAP_PARAM_ERROR, 'SASL requires LDAPv3')
#       if $ldap->{net_ldap_version} < 3;
# 
#     my $sasl = $passwd;
#     my $sasl_conn;
# 
#     if (ref($sasl) and $sasl->isa('Authen::SASL')) {
# 
#       # If we're talking to a round-robin, the canonical name of
#       # the host we are talking to might not match the name we
#       # requested. Look at the rawsocket because SASL layer filehandles
#       # don't support socket methods.
#       my $sasl_host;
# 
#       if (exists($arg->{sasl_host})) {
#         if ($arg->{sasl_host}) {
#           $sasl_host = $arg->{sasl_host};
#         }
#         elsif ($ldap->{net_ldap_rawsocket}->can('peerhost')) {
#           $sasl_host = $ldap->{net_ldap_rawsocket}->peerhost;
#         }
#       }
#       $sasl_host ||= $ldap->{net_ldap_host};
# 
#       $sasl_conn = eval {
#         local ($SIG{__DIE__});
#         $sasl->client_new('ldap', $sasl_host);
#       };
#     }
#     else {
#       $sasl_conn = $sasl;
#     }
# 
#     return _error($ldap, $mesg, LDAP_LOCAL_ERROR, "$@")
#       unless defined($sasl_conn);
# 
#     # Tell SASL the local and server IP addresses
#     $sasl_conn->property(
#       sockname => $ldap->{net_ldap_rawsocket}->sockname,
#       peername => $ldap->{net_ldap_rawsocket}->peername,
#     );
# 
#     my $initial = $sasl_conn->client_start;
# 
#     return _error($ldap, $mesg, LDAP_LOCAL_ERROR, $sasl_conn->error)
#       unless defined($initial);
# 
#     $passwd = {
#       mechanism   => $sasl_conn->mechanism,
#       credentials => $initial,
#     };
# 
#     # Save data, we will need it later
#     $mesg->_sasl_info($stash{name}, $control, $sasl_conn);
#   }
# 
#   $stash{authentication} = { $auth_type => $passwd };
# 
#   $mesg->encode(
#     bindRequest => \%stash,
#     controls    => $control
#   ) or return _error($ldap, $mesg, LDAP_ENCODING_ERROR, "$@");
# 
#   $ldap->_sendmesg($mesg);
# }
# 
# 
# my %scope = qw(base  0 one    1 single 1 sub    2 subtree 2 children 3);
# my %deref = qw(never 0 search 1 find   2 always 3);
# 
# sub search {
#   my $ldap = shift;
#   my $arg  = &_options;
# 
#   require Net::LDAP::Search;
# 
#   $arg->{raw} = $ldap->{raw}
#     if ($ldap->{raw} && !defined($arg->{raw}));
# 
#   my $mesg = $ldap->message('Net::LDAP::Search' => $arg);
# 
#   my $control = $arg->{control}
#     and $ldap->{net_ldap_version} < 3
#     and return _error($ldap, $mesg, LDAP_PARAM_ERROR, 'Controls require LDAPv3');
# 
#   my $base = $arg->{base} || '';
#   my $filter;
# 
#   unless (ref ($filter = $arg->{filter})) {
#     require Net::LDAP::Filter;
#     my $f = Net::LDAP::Filter->new;
#     $f->parse($filter)
#       or return _error($ldap, $mesg, LDAP_PARAM_ERROR, 'Bad filter');
#     $filter = $f;
#   }
# 
#   my %stash = (
#     baseObject   => ref($base) ? $base->dn : $base,
#     scope        => 2,
#     derefAliases => 2,
#     sizeLimit    => $arg->{sizelimit} || 0,
#     timeLimit    => $arg->{timelimit} || 0,
#     typesOnly    => $arg->{typesonly} || $arg->{attrsonly} || 0,
#     filter       => $filter,
#     attributes   => $arg->{attrs} || []
#   );
# 
#   if (exists $arg->{scope}) {
#     my $sc = lc $arg->{scope};
#     $stash{scope} = 0 + (exists $scope{$sc} ? $scope{$sc} : $sc);
#   }
# 
#   if (exists $arg->{deref}) {
#     my $dr = lc $arg->{deref};
#     $stash{derefAliases} = 0 + (exists $deref{$dr} ? $deref{$dr} : $dr);
#   }
# 
#   $mesg->encode(
#     searchRequest => \%stash,
#     controls      => $control
#   ) or return _error($ldap, $mesg, LDAP_ENCODING_ERROR, "$@");
# 
#   $ldap->_sendmesg($mesg);
# }
# 
# 
# sub add {
#   my $ldap = shift;
#   my $arg  = &_dn_options;
# 
#   my $mesg = $ldap->message('Net::LDAP::Add' => $arg);
# 
#   my $control = $arg->{control}
#     and $ldap->{net_ldap_version} < 3
#     and return _error($ldap, $mesg, LDAP_PARAM_ERROR, 'Controls require LDAPv3');
# 
#   my $entry = $arg->{dn}
#     or return _error($ldap, $mesg, LDAP_PARAM_ERROR, 'No DN specified');
# 
#   unless (ref $entry) {
#     require Net::LDAP::Entry;
#     $entry = Net::LDAP::Entry->new;
#     $entry->dn($arg->{dn});
#     $entry->add(@{$arg->{attrs} || $arg->{attr} || []});
#   }
# 
#   $mesg->encode(
#     addRequest => $entry->asn,
#     controls   => $control
#   ) or return _error($ldap, $mesg, LDAP_ENCODING_ERROR, "$@");
# 
#   $ldap->_sendmesg($mesg);
# }
# 
# 
# my %opcode = ( add => 0, delete => 1, replace => 2, increment => 3 );
# 
# sub modify {
#   my $ldap = shift;
#   my $arg  = &_dn_options;
# 
#   my $mesg = $ldap->message('Net::LDAP::Modify' => $arg);
# 
#   my $control = $arg->{control}
#     and $ldap->{net_ldap_version} < 3
#     and return _error($ldap, $mesg, LDAP_PARAM_ERROR, 'Controls require LDAPv3');
# 
#   my $dn = $arg->{dn}
#     or return _error($ldap, $mesg, LDAP_PARAM_ERROR, 'No DN specified');
# 
#   my @ops;
#   my $opcode;
# 
#   if (exists $arg->{changes}) {
#     my $opcode;
#     my $j = 0;
#     while ($j < @{$arg->{changes}}) {
#       return _error($ldap, $mesg, LDAP_PARAM_ERROR, "Bad change type '" . $arg->{changes}[--$j] . "'")
#        unless defined($opcode = $opcode{$arg->{changes}[$j++]});
# 
#       my $chg = $arg->{changes}[$j++];
#       if (ref($chg)) {
# 	my $i = 0;
# 	while ($i < @$chg) {
#           push @ops, {
# 	    operation => $opcode,
# 	    modification => {
# 	      type => $chg->[$i],
# 	      vals => ref($chg->[$i+1]) ? $chg->[$i+1] : [$chg->[$i+1]]
# 	    }
# 	  };
# 	  $i += 2;
# 	}
#       }
#     }
#   }
#   else {
#     foreach my $op (qw(add delete replace increment)) {
#       next  unless exists $arg->{$op};
#       my $opt = $arg->{$op};
#       my $opcode = $opcode{$op};
# 
#       if (ref($opt) eq 'HASH') {
# 	while (my ($k, $v) = each %$opt) {
#           push @ops, {
# 	    operation => $opcode,
# 	    modification => {
# 	      type => $k,
# 	      vals => ref($v) ? $v : [$v]
# 	    }
# 	  };
# 	}
#       }
#       elsif (ref($opt) eq 'ARRAY') {
# 	my $k = 0;
# 
# 	while ($k < @{$opt}) {
#           my $attr = ${$opt}[$k++];
#           my $val = $opcode == 1 ? [] : ${$opt}[$k++];
#           push @ops, {
# 	    operation => $opcode,
# 	    modification => {
# 	      type => $attr,
# 	      vals => ref($val) ? $val : [$val]
# 	    }
# 	  };
# 	}
#       }
#       else {
# 	push @ops, {
# 	  operation => $opcode,
# 	  modification => {
# 	    type => $opt,
# 	    vals => []
# 	  }
# 	};
#       }
#     }
#   }
# 
#   $mesg->encode(
#     modifyRequest => {
#       object       => ref($dn) ? $dn->dn : $dn,
#       modification => \@ops
#     },
#     controls => $control
#   ) or return _error($ldap, $mesg, LDAP_ENCODING_ERROR, "$@");
# 
#   $ldap->_sendmesg($mesg);
# }
# 
# sub delete {
#   my $ldap = shift;
#   my $arg  = &_dn_options;
# 
#   my $mesg = $ldap->message('Net::LDAP::Delete' => $arg);
# 
#   my $control = $arg->{control}
#     and $ldap->{net_ldap_version} < 3
#     and return _error($ldap, $mesg, LDAP_PARAM_ERROR, 'Controls require LDAPv3');
# 
#   my $dn = $arg->{dn}
#     or return _error($ldap, $mesg, LDAP_PARAM_ERROR, 'No DN specified');
# 
#   $mesg->encode(
#     delRequest => ref($dn) ? $dn->dn : $dn,
#     controls   => $control
#   ) or return _error($ldap, $mesg, LDAP_ENCODING_ERROR, "$@");
# 
#   $ldap->_sendmesg($mesg);
# }
# 
# sub moddn {
#   my $ldap = shift;
#   my $arg  = &_dn_options;
#   my $del  = $arg->{deleteoldrdn} || $arg->{delete} || 0;
#   my $newsup = $arg->{newsuperior};
# 
#   my $mesg = $ldap->message('Net::LDAP::ModDN' => $arg);
# 
#   my $control = $arg->{control}
#     and $ldap->{net_ldap_version} < 3
#     and return _error($ldap, $mesg, LDAP_PARAM_ERROR, 'Controls require LDAPv3');
# 
#   my $dn = $arg->{dn}
#     or return _error($ldap, $mesg, LDAP_PARAM_ERROR, 'No DN specified');
# 
#   my $new  = $arg->{newrdn} || $arg->{new}
#     or return _error($ldap, $mesg, LDAP_PARAM_ERROR, 'No NewRDN specified');
# 
#   $mesg->encode(
#     modDNRequest => {
#       entry        => ref($dn) ? $dn->dn : $dn,
#       newrdn       => ref($new) ? $new->dn : $new,
#       deleteoldrdn => $del,
#       newSuperior  => ref($newsup) ? $newsup->dn : $newsup,
#     },
#     controls => $control
#   ) or return _error($ldap, $mesg, LDAP_ENCODING_ERROR, "$@");
# 
#   $ldap->_sendmesg($mesg);
# }
# 
# # now maps to the V3/X.500(93) modifydn map
# sub modrdn { goto &moddn }
# 
# sub compare {
#   my $ldap  = shift;
#   my $arg   = &_dn_options;
# 
#   my $mesg = $ldap->message('Net::LDAP::Compare' => $arg);
# 
#   my $control = $arg->{control}
#     and $ldap->{net_ldap_version} < 3
#     and return _error($ldap, $mesg, LDAP_PARAM_ERROR, 'Controls require LDAPv3');
# 
#   my $dn = $arg->{dn}
#     or return _error($ldap, $mesg, LDAP_PARAM_ERROR, 'No DN specified');
# 
#   my $attr = exists $arg->{attr}
# 		? $arg->{attr}
# 		: exists $arg->{attrs} #compat
# 		   ? $arg->{attrs}[0]
# 		   : '';
# 
#   my $value = exists $arg->{value}
# 		? $arg->{value}
# 		: exists $arg->{attrs} #compat
# 		   ? $arg->{attrs}[1]
# 		   : '';
# 
# 
#   $mesg->encode(
#     compareRequest => {
#       entry => ref($dn) ? $dn->dn : $dn,
#       ava   => {
# 	attributeDesc  => $attr,
# 	assertionValue => $value
#       }
#     },
#     controls => $control
#   ) or return _error($ldap, $mesg, LDAP_ENCODING_ERROR, "$@");
# 
#   $ldap->_sendmesg($mesg);
# }
# 
# sub abandon {
#   my $ldap = shift;
#   unshift @_, 'id'  if @_ & 1;
#   my $arg = &_options;
# 
#   my $id = $arg->{id};
# 
#   my $mesg = $ldap->message('Net::LDAP::Abandon' => $arg);
# 
#   my $control = $arg->{control}
#     and $ldap->{net_ldap_version} < 3
#     and return _error($ldap, $mesg, LDAP_PARAM_ERROR, 'Controls require LDAPv3');
# 
#   $mesg->encode(
#     abandonRequest => ref($id) ? $id->mesg_id : $id,
#     controls       => $control
#   ) or return _error($ldap, $mesg, LDAP_ENCODING_ERROR, "$@");
# 
#   $ldap->_sendmesg($mesg);
# }
# 
# sub extension {
#   my $ldap = shift;
#   my $arg  = &_options;
# 
#   require Net::LDAP::Extension;
#   my $mesg = $ldap->message('Net::LDAP::Extension' => $arg);
# 
#   return _error($ldap, $mesg, LDAP_LOCAL_ERROR, 'ExtendedRequest requires LDAPv3')
#     if $ldap->{net_ldap_version} < 3;
# 
#   $mesg->encode(
#     extendedReq => {
#       requestName  => $arg->{name},
#       requestValue => $arg->{value}
#     },
#     controls => $arg->{control}
#   ) or return _error($ldap, $mesg, LDAP_ENCODING_ERROR, "$@");
# 
#   $ldap->_sendmesg($mesg);
# }
# 
# sub sync {
#   my $ldap  = shift;
#   my $mid   = shift;
#   my $table = $ldap->{net_ldap_mesg};
#   my $err   = LDAP_SUCCESS;
# 
#   return $err  unless defined $table;
# 
#   $mid = $mid->mesg_id  if ref($mid);
#   while (defined($mid) ? exists $table->{$mid} : %$table) {
#     last  if $err = $ldap->process($mid);
#   }
# 
#   $err;
# }
# 
# sub disconnect {
#   my $self = shift;
#   _drop_conn($self, LDAP_USER_CANCELED, 'Explicit disconnect');
# }
# 
# sub _sendmesg {
#   my $ldap = shift;
#   my $mesg = shift;
# 
#   my $debug;
#   if ($debug = $ldap->debug) {
#     require Convert::ASN1::Debug;
#     print STDERR "$ldap sending:\n";
# 
#     Convert::ASN1::asn_hexdump(*STDERR, $mesg->pdu)
#       if $debug & 1;
# 
#     Convert::ASN1::asn_dump(*STDERR, $mesg->pdu)
#       if $debug & 4;
#   }
# 
#   my $socket = $ldap->socket
#     or return _error($ldap, $mesg, LDAP_SERVER_DOWN, "$!");
# 
#   # send packets in sizes that IO::Socket::SSL can chew
#   # originally it was:
#   #syswrite($socket, $mesg->pdu, length($mesg->pdu))
#   #  or return _error($ldap, $mesg, LDAP_LOCAL_ERROR, "$!")
#   my $to_send = \( $mesg->pdu );
#   my $offset = 0;
#   while ($offset < length($$to_send)) {
#     my $s = substr($$to_send, $offset, 15000);
#     my $n = syswrite($socket, $s, length($s))
#       or return _error($ldap, $mesg, LDAP_LOCAL_ERROR, "$!");
#     $offset += $n;
#   }
# 
#   # for CLDAP, here we need to recode when we were sent
#   # so that we can perform timeouts and resends
# 
#   my $mid  = $mesg->mesg_id;
#   my $sync = not $ldap->async;
# 
#   unless ($mesg->done) { # may not have a response
# 
#     $ldap->{net_ldap_mesg}->{$mid} = $mesg;
# 
#     if ($sync) {
#       my $err = $ldap->sync($mid);
#       return _error($ldap, $mesg, $err, $@)  if $err;
#     }
#   }
# 
#   $sync && $ldap->{net_ldap_onerror} && $mesg->is_error
#     ? scalar &{$ldap->{net_ldap_onerror}}($mesg)
#     : $mesg;
# }
# 
# sub data_ready {
#   my $ldap = shift;
#   my $sock = $ldap->socket  or return;
#   my $sel = IO::Select->new($sock);
# 
#   return defined $sel->can_read(0) || (ref($sock) eq 'IO::Socket::SSL' && $sock->pending());
# }
# 
# sub process {
#   my $ldap = shift;
#   my $what = shift;
#   my $sock = $ldap->socket  or return LDAP_SERVER_DOWN;
# 
#   for (my $ready = 1; $ready; $ready = $ldap->data_ready) {
#     my $pdu;
#     asn_read($sock, $pdu)
#       or return _drop_conn($ldap, LDAP_OPERATIONS_ERROR, 'Communications Error');
# 
#     my $debug;
#     if ($debug = $ldap->debug) {
#       require Convert::ASN1::Debug;
#       print STDERR "$ldap received:\n";
# 
#       Convert::ASN1::asn_hexdump(\*STDERR, $pdu)
# 	if $debug & 2;
# 
#       Convert::ASN1::asn_dump(\*STDERR, $pdu)
# 	if $debug & 8;
#     }
# 
#     my $result = $LDAPResponse->decode($pdu)
#       or return LDAP_DECODING_ERROR;
# 
#     my $mid  = $result->{messageID};
#     my $mesg = $ldap->{net_ldap_mesg}->{$mid};
# 
#     unless ($mesg) {
#       if (my $ext = $result->{protocolOp}{extendedResp}) {
# 	if (($ext->{responseName} || '') eq '1.3.6.1.4.1.1466.20036') {
# 	  # notice of disconnection
# 	  return _drop_conn($ldap, LDAP_SERVER_DOWN, 'Notice of Disconnection');
# 	}
#       }
# 
#       print STDERR "Unexpected PDU, ignored\n"  if $debug & 10;
#       next;
#     }
# 
#     $mesg->decode($result)
#       or return $mesg->code;
# 
#     last  if defined $what && $what == $mid;
#   }
# 
#   # FIXME: in CLDAP here we need to check if any message has timed out
#   # and if so do we resend it or what
# 
#   return LDAP_SUCCESS;
# }
# 
# *_recvresp = \&process; # compat
# 
# sub _drop_conn {
#   my ($self, $err, $etxt) = @_;
# 
#   delete $self->{net_ldap_rawsocket};
#   my $sock = delete $self->{net_ldap_socket};
#   close($sock)  if $sock;
# 
#   if (my $msgs = delete $self->{net_ldap_mesg}) {
#     foreach my $mesg (values %$msgs) {
#       next  unless (defined $mesg);
#       $mesg->set_error($err, $etxt);
#     }
#   }
# 
#   $err;
# }
# 
# 
# sub _forgetmesg {
#   my $ldap = shift;
#   my $mesg = shift;
# 
#   my $mid = $mesg->mesg_id;
# 
#   delete $ldap->{net_ldap_mesg}->{$mid};
# }
# 
# #Mark Wilcox 3-20-2000
# #now accepts named parameters
# #dn => "dn of subschema entry"
# #
# #
# # Clif Harden 2-4-2001.
# # corrected filter for subschema search.
# # added attributes to retrieve on subschema search.
# # added attributes to retrieve on rootDSE search.
# # changed several double quote character to single quote
# # character, just to be consistent throughout the schema
# # and root_dse functions.
# #
# 
# sub schema {
#   require Net::LDAP::Schema;
#   my $self = shift;
#   my %arg = @_;
#   my $base;
#   my $mesg;
# 
#   if (exists $arg{dn}) {
#     $base = $arg{dn};
#   }
#   else {
#     my $root = $self->root_dse( attrs => ['subschemaSubentry'] )
#       or return undef;
# 
#     $base = $root->get_value('subschemaSubentry') || 'cn=schema';
#   }
# 
#   $mesg = $self->search(
#     base   => $base,
#     scope  => 'base',
#     filter => '(objectClass=subschema)',
#     attrs  => [qw(
# 		objectClasses
# 		attributeTypes
# 		matchingRules
# 		matchingRuleUse
# 		dITStructureRules
# 		dITContentRules
# 		nameForms
# 		ldapSyntaxes
#                 extendedAttributeInfo
#               )],
#   );
# 
#   $mesg->code
#     ? undef
#     : Net::LDAP::Schema->new($mesg->entry);
# }
# 
# 
# sub root_dse {
#   my $ldap = shift;
#   my %arg  = @_;
#   my $attrs = $arg{attrs} || [qw(
# 		  subschemaSubentry
# 		  namingContexts
# 		  altServer
# 		  supportedExtension
# 		  supportedControl
# 		  supportedFeatures
# 		  supportedSASLMechanisms
# 		  supportedLDAPVersion
# 		  vendorName
# 		  vendorVersion
# 		)];
#   my $root = $arg{attrs} && $ldap->{net_ldap_root_dse};
# 
#   return $root  if $root;
# 
#   my $mesg = $ldap->search(
#     base   => '',
#     scope  => 'base',
#     filter => '(objectClass=*)',
#     attrs  => $attrs,
#   );
# 
#   require Net::LDAP::RootDSE;
#   $root = $mesg->entry;
#   bless $root, 'Net::LDAP::RootDSE'  if $root; # Naughty, but there you go :-)
# 
#   $ldap->{net_ldap_root_dse} = $root  unless $arg{attrs};
# 
#   return $root;
# }
# 
# sub start_tls {
#   my $ldap = shift;
#   my $arg  = &_options;
#   my $sock = $ldap->socket;
# 
#   require IO::Socket::SSL;
#   require Net::LDAP::Extension;
#   my $mesg = $ldap->message('Net::LDAP::Extension' => $arg);
# 
#   return _error($ldap, $mesg, LDAP_OPERATIONS_ERROR, 'TLS already started')
#     if $sock->isa('IO::Socket::SSL');
# 
#   return _error($ldap, $mesg, LDAP_PARAM_ERROR, 'StartTLS requires LDAPv3')
#     if $ldap->version < 3;
# 
#   $mesg->encode(
#     extendedReq => {
#       requestName => LDAP_EXTENSION_START_TLS,
#     }
#   );
# 
#   $ldap->_sendmesg($mesg);
#   $mesg->sync();
# 
#   return $mesg
#     if $mesg->code;
# 
#   delete $ldap->{net_ldap_root_dse};
# 
#   $arg->{sslserver} = $ldap->{net_ldap_host}  unless defined $arg->{sslserver};
# 
#   my $sock_class = ref($sock);
# 
#   return $mesg
#     if IO::Socket::SSL->start_SSL($sock, {_SSL_context_init_args($arg)});
# 
#   my $err = $@ || $IO::Socket::SSL::SSL_ERROR || $IO::Socket::SSL::SSL_ERROR || ''; # avoid use on once warning
# 
#   if ($sock_class ne ref($sock)) {
#     $err = $sock->errstr;
#     bless $sock, $sock_class;
#   }
# 
#   _error($ldap, $mesg, LDAP_OPERATIONS_ERROR, $err);
# }
# 
# sub cipher {
#   my $ldap = shift;
#   $ldap->socket->isa('IO::Socket::SSL')
#     ? $ldap->socket->get_cipher
#     : undef;
# }
# 
# sub certificate {
#   my $ldap = shift;
#   $ldap->socket->isa('IO::Socket::SSL')
#     ? $ldap->socket->get_peer_certificate
#     : undef;
# }
# 
# # what version are we talking?
# sub version {
#   my $ldap = shift;
# 
#   @_
#     ? ($ldap->{net_ldap_version}, $ldap->{net_ldap_version} = shift)[0]
#     : $ldap->{net_ldap_version};
# }
# 
# sub outer {
#   my $self = shift;
#   return $self  if tied(%$self);
#   my %outer;
#   tie %outer, ref($self), $self;
#   ++$self->{net_ldap_refcnt};
#   bless \%outer, ref($self);
# }
# 
# sub inner {
#   tied(%{$_[0]}) || $_[0];
# }
# 
# sub TIEHASH {
#   $_[1];
# }
# 
# sub DESTROY {
#   my $ldap = shift;
#   my $inner = tied(%$ldap)  or return;
#   _drop_conn($inner, LDAP_UNAVAILABLE, 'Implicit disconnect')
#     unless --$inner->{net_ldap_refcnt};
# }
# 
# 1;
# =end old
