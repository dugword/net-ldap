# Copyright (c) 1997-2004 Graham Barr <gbarr@pobox.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

# unit class Net::LDAP::Filter;

# use Data::Dump;

# filter       = "(" filtercomp ")"
# filtercomp   = and / or / not / item
# and          = "&" filterlist
# or           = "|" filterlist
# not          = "!" filter
# filterlist   = 1*filter
# item         = simple / present / substring / extensible
# simple       = attr filtertype value
# filtertype   = equal / approx / greater / less
# equal        = "="
# approx       = "~="
# greater      = ">="
# less         = "<="
# extensible   = attr [":dn"] [":" matchingrule] ":=" value
#                / [":dn"] ":" matchingrule ":=" value
# present      = attr "=*"
# substring    = attr "=" [initial] any [final]
# initial      = value
# any          = "*" *(value "*")
# final        = value
# attr         = AttributeDescription from Section 2.5 of RFC 4512
# matchingrule = MatchingRuleId from Section 4.1.8 of RFC 4511
# value        = AttributeValue from Section 4.1.6 of RFC 4511
#                with some characters encoded, see below.
#
# Special Character encodings
# ---------------------------
#    *               \2a, \*
#    (               \28, \(
#    )               \29, \)
#    \               \5c, \\
#    NUL             \00

class Net::LDAP::Filter {

    my $ErrStr;

# sub new {
#   my $self = shift;
#   my $class = ref($self) || $self;
# 
#   my $me = bless {}, $class;
# 
#   if (@_) {
#     $me.parse(shift) or
#       return Any;
#   }
#   $me;
# }

    my $Attr  = '[-;.:\d\w]*[-;\d\w]';

    my %Op = qw (
    &   and
    |   or
    !   not
    =   equalityMatch
    ~=  approxMatch
    >=  greaterOrEqual
    <=  lessOrEqual
    :=  extensibleMatch
    );

    my %Rop = reverse %Op;


    sub errstr { $ErrStr }

# Unescape
#   \xx where xx is a 2-digit hex number
#   \y  where y is one of ( ) \ *
    sub _unescape ($token) {

        if $token ~~ /
            \\(<[ \d a..f A..F ]> ** 2 || <[()\\*]>)
        / {
            $token = $0.chars == 1 ?? $0 !! :16($0).chr;
        }

        return $token;

#   @_[0] ~~ s:sxec:P5/
# 	     \\([\da-fA-F]{2}|[()\\*])
# 	    /
# 	     length($1) == 1
# 	       ? $1
# 	       : chr(hex($1))
# 	    /;
#   @_[0];
    }

    sub _escape($token) { 
            $token ~~ /
                <[ \\ ( ) * \x00..\x1f \x7f..\xff ]>
            /;

            my $value = sprintf('\\%02x', $0.ord);

            return $value;
            # (my $t = @_[0]) ~~ s:sce:P5/([\\\(\)\*\0-\37\177-\377])/sprintf('\\%02x', ord($1))/; $t
    }

# encode a triplet ($attr,$op,$val) representing a single filter item
    sub _encode {
    my ($attr, $op, $val) = @_;

    # extensible match
    if ($op eq ':=') {

        # attr must be in the form type:dn:1.2.3.4
        unless ($attr ~~ m:P5/^([-;\d\w]*)(:dn)?(:(\w+|[.\d]+))?$/) {
        $ErrStr = "Bad attribute $attr";
        return Any;
        }
        my ($type, $dn, $rule) = ($0, $1, $3);

        return ( {
        extensibleMatch => {
        matchingRule => $rule,
        type         => ($type.chars) ?? $type !! Any,
        matchValue   => _unescape($val),
        dnAttributes => $dn ?? 1 !! Any
        }
        });
    }

    # special cases: present / substring match
    if ($op eq '=') {

        # present match
        if ($val eq '*') {
        return ({ present => $attr });
        }

        # if val contains unescaped *, then we have substring match
        elsif ( $val ~~ m:P5/^(\\.|[^\\*]+)*\*/ ) {

        my $n = [];
        my $type = 'initial';

        while ($val ~~ s:P5/^((\\.|[^\\*]+)*)\*//) {
        push(@$n, { $type, _unescape("$1") })         # $1 is readonly, copy it
        if $0.chars or $type eq 'any';

        $type = 'any';
        }

        push(@$n, { 'final', _unescape($val) })
        if  $val.chars;

        return ({
        substrings => {
        type       => $attr,
        substrings => $n
        }
        });
        }
    }

    # in all other cases we must have an operator and no un-escaped *'s on the RHS
    return {
        %Op{$op} => {
        attributeDesc => $attr, assertionValue =>  _unescape($val)
        }
    };
    }

# parse & encode a filter string
    method parse ($filter is copy) {

    my @stack;
    my @cur;
    my $op;

    $ErrStr = '';

    # a filter is required
    unless $filter {
        die 'Undefined filter';
        return Any;
    }

    # Algorithm depends on /^ \( /;
    $filter ~~ s/^ \s* //;

    $filter = '(' ~ $filter ~ ')'
        unless $filter ~~ / ^\( /;

    while $filter.chars {

        # Process the start of  (<op> (...)(...)), with <op> = [&!|]

        if ($filter ~~ s/^ \( \s* (<[ & ! | ]>) \s* //) {
            @stack.push([$op, @cur]);
            $op = $0;
            @cur = [];
            next;
        }

        # Process the end of  (<op> (...)(...)), with <op> = [&!|]

        elsif $filter ~~ s/^ \) \s* // {
            unless (@stack) {
                die 'Bad filter, unmatched )';
            }

            my $myop = $op;
            my @mydata = @cur.values;
            ($op, @cur) = @( @stack.pop );
            # Need to do more checking here
            @cur.push( { %Op{$myop} => $myop eq '!' ?? @mydata[0] !! @mydata });
            next if @stack;
        }

        # process (attr op string)

        elsif $filter ~~ s/^
            \( \s*
            (<[ - ; . : \d \w ]>* <[ - ; \d \w ]>) \s*
            (<[ : ~ < > ]>? \=)
            ([ \\ . || <-[ \\ ( ) ]>+ ]*)
            \)\s*
        // {
            push(@cur, _encode("$0", "$1", "$2"));
            next  if @stack;
        }

        # If we get here then there is an error in the filter string
        # so exit loop with data in $filter
        last;
    }

    if  $filter.chars {
        # If we have anything left in the filter, then there is a problem
        $ErrStr = 'Bad filter, error before ' ~ substr($filter, 0, 20);
        say "Here in the filter chars remaining";
        return Any;
    }
    if (@stack) {
        $ErrStr = 'Bad filter, unmatched (';
        say "Here in the stack";
        return Any;
    }

    say "Cur";
    dd @cur;
    say "End cur";
    return @cur[1];
    }

    sub print {
        die "Why would you want to print from this class, just all print...";
    # my $self = shift;
    # select may return a GLOB name
    # my $fh = @_ ?? (shift) !! (select);

    # print $fh $self.as_string, "\n";
    }

    sub as_string { _string(%(@_[0])) }

    sub _string (@string) {    # prints things of the form (<op> (<list>) ... )
    my $str = '';

    for (@string[0]) {
        m:P5/^and/  and return '(&' ~ join('', map { _string(%$_) }, @(@string[1])) ~ ')';
        m:P5/^or/   and return '(|' ~ join('', map { _string(%$_) }, @(@string[1])) ~ ')';
        m:P5/^not/  and return '(!' ~ _string(%(@string[1])) ~ ')';
        m:P5/^present/  and return "\($_[1]=*\)";
        m:P5/^(equalityMatch|greaterOrEqual|lessOrEqual|approxMatch)/
        and return '(' ~ @string[1].{'attributeDesc'} ~ %Rop{'$1'} ~ _escape(@string[1].{'assertionValue'})  ~')';
        m:P5/^substrings/  and do {
        my $str = join('*', '', map { _escape($_) }, map { values %$_ }, @(@string[1].{'substrings'}));
        $str ~~ s:P5/^.//  if @string[1].{'substrings'}[0]{'initial'}:exists;
        $str ~= '*'  unless @string[1].{'substrings'}[*-1]{'final'}:exists;
        return "\($_[1].{"type"}=$str\)";
        };
        m:P5/^extensibleMatch/  and do {
        my $str = '(';
        $str ~= @string[1].{'type'}  if defined @string[1].{'type'};
        $str ~= ':dn'  if @string[1].{'dnAttributes'};
        $str ~= ":$_[1].{"matchingRule"}"  if defined @string[1].{'matchingRule'};
        $str ~= ':=' ~ _escape(@string[1].{'matchValue'}) ~ ')';
        return $str;
        };
    }

    die "Internal error $_[0]";
    }

    sub negate {
    die "What is this even for?";
#   my $self = shift;
# 
#   %($self) = _negate(%($self));
# 
#   $self;
    }

    sub _negate {    # negate a filter tree
    for (@_[0]) {
        m:P5/^and/  and return ( 'or' => [ map { { _negate(%$_) }; }, @(@_[1]) ] );
        m:P5/^or/   and return ( 'and' => [ map { { _negate(%$_) }; }, @(@_[1]) ] );
        m:P5/^not/  and return %(@_[1]);
        m:P5/^(present|equalityMatch|greaterOrEqual|lessOrEqual|approxMatch|substrings|extensibleMatch)/
        and  do return ( 'not' => { @_[0 ], @_[1] } );
    }

    die "Internal error $_[0]";
    }

}
