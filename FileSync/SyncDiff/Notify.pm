#!/usr/bin/perl

###########################################################################
# Copyright (C) 2014  John 'Warthog9' Hawley                              #
#                         jhawley@redhat.com                              #
#                         warthog9@eaglescrag.net                         #
#                                                                         #
# This file is originally part of SyncDiff(erent).                        #
#                                                                         #
# This library is free software; you can redistribute it and/or           #
# modify it under the terms of the GNU Lesser General Public              #
# License as published by the Free Software Foundation; either            #
# version 2.1 of the License, or (at your option) any later version.      #
#                                                                         #
# This library is distributed in the hope that it will be useful,         #
# but WITHOUT ANY WARRANTY; without even the implied warranty of          #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       #
# Lesser General Public License for more details.                         #
#                                                                         #
# You should have received a copy of the GNU Lesser General Public        #
# License along with this library; if not, write to the:                  #
#    Free Software Foundation, Inc.                                       #
#    51 Franklin Street                                                   #
#    Fifth Floor                                                          #
#    Boston, MA  02110-1301                                               #
#    USA                                                                  #
#                                                                         #
# Or, see <http://www.gnu.org/licenses/>.                                 #
###########################################################################

package FileSync::SyncDiff::Notify;
$FileSync::SyncDiff::Notify::VERSION = '0.01';

use Moose;
use namespace::clean;

extends qw(FileSync::SyncDiff::Forkable);

use FileSync::SyncDiff::Scanner;
use FileSync::SyncDiff::Config;
use FileSync::SyncDiff::Log;

use AnyEvent;
use JSON::XS qw(encode_json);
use Net::Address::IP::Local;
use File::Spec::Functions qw(catfile);
use Net::Ping qw();

use Data::Dumper;

use constant SUBSYSTEM_NAME => 'Notify';

has 'config' => (
    is       => 'rw',
    isa      => 'FileSync::SyncDiff::Config',
    required => 1,
);

has 'dbref' => (
    is       => 'rw',
    isa      => 'Object',
    required => 1,
);

# Logger system
has 'log' => (
    is      => 'rw',
    isa     => 'FileSync::SyncDiff::Log',
    default => sub {
        my $self = shift;
        return FileSync::SyncDiff::Log->new( config => $self->config );
    }
);

sub run {
    my $self = shift;

    if ( !$self->_is_running() ) {
        $self->_clean();
        $self->fork();
    }
    else {
        $self->log->debug("'Notify' subsystem already running");
    }
}

override 'run_child' => sub {
    my ($self) = @_;

    $self->_start();
    $self->_load_plugin();
};

sub _start {
    my ($self) = @_;
    return $self->dbref->new_subsystem( { name => SUBSYSTEM_NAME, pid => $$ } );
}

sub _is_running {
    my ($self) = @_;

    my $info = $self->dbref->get_subsystem( { name => SUBSYSTEM_NAME } );
    my $is_running = 0;
    if ($info) {
        my $is_exists = $info->{&SUBSYSTEM_NAME}{pid} && kill( 0, $info->{&SUBSYSTEM_NAME}{pid} ) ? 1 : 0;
        my $is_enabled = $info->{&SUBSYSTEM_NAME}{enable} ? 1 : 0;
        $is_running = $is_enabled && $is_exists ? 1 : 0;
    }

    return $is_running;
}

sub _clean {
    my ($self) = @_;
    return $self->dbref->clean_subsystems( { name => SUBSYSTEM_NAME } );
}

sub _load_plugin {
    my $self = shift;

    if ( $^O =~ /linux/i ) {
        require FileSync::SyncDiff::Notify::Plugin::Inotify2;
        $self->_load_linux();
    }
    elsif ( $^O =~ /bsd/i || $^O =~ /darwin/i ) {
        require FileSync::SyncDiff::Notify::Plugin::KQueue;
        $self->_load_bsd();
    }
    else {
        $self->log->error( "%s is not supported!", $^O );
    }

    return 1;
}

sub _load_linux {
    my $self = shift;

    my @dirs;
    for my $group_data ( values %{ $self->config->config->{groups} } ) {
        push( @dirs, $group_data->{patterns} );
    }

    my $cv = AnyEvent->condvar;

    my $inotify = FileSync::SyncDiff::Notify::Plugin::Inotify2->new(
        dirs           => @dirs,
        event_receiver => sub {
            $self->_process_events(@_);
        }
    );

    $cv->recv;
}

sub _load_bsd {
    my $self = shift;

    my @dirs;
    for my $group_data ( values %{ $self->config->config->{groups} } ) {
        push( @dirs, $group_data->{patterns} );
    }

    my $cv = AnyEvent->condvar;

    my $kqueue = FileSync::SyncDiff::Notify::Plugin::KQueue->new(
        includes       => @dirs,
        event_receiver => sub {
            $self->_process_events(@_);
        }
    );

    $cv->recv;
}

sub _process_events {
    my ( $self, $event, $file, $groupbase ) = @_;

    if ( $event eq 'modify' ) {
        while ( my ( $group_name, $group_data ) = each( %{ $self->config->config->{groups} } ) ) {
            # Need to notify only those groups which contain a true include
            # for file which was modified
            next if ( !grep { $_ eq $groupbase } @{ $group_data->{patterns} } );

            # Send notify request on localhost(server and notify-server on the same side)
            $self->_send_notify_request( {
                    host       => '127.0.0.1',
                    port       => 7070,
                    group_name => $group_name,
                }
            );

            # Send notify request on other hosts(if it's needed)
            for my $host ( @{ $group_data->{host} } ) {
                my $p = Net::Ping->new();
                if ( !$p->ping( $host->{host} ) ) {
                    $self->log->debug( "%s is not alive!", $host->{host} );
                    next;
                }
                $p->close();

                $self->_send_notify_request( {
                        host       => $host->{host},
                        port       => 7070,
                        group_name => $group_name,
                    }
                );
            }
        } ## end while ( my ( $group_name,...))
    } ## end if ( $event eq 'modify')
} ## end sub _process_events

sub _send_notify_request {
    my ( $self, $info ) = @_;

    my $sock = eval { IO::Socket::INET->new( PeerAddr => $info->{host}, PeerPort => $info->{port}, Proto => 'tcp', ); };
    if ( !$sock ) {
        $self->log->error( "Could not create socket: %s", $! );
        return;
    }    # end skipping if the socket is broken

    $sock->autoflush(1);

    my %request = (
        'operation' => 'notify',
        'hostname'  => Net::Address::IP::Local->public,
        'group'     => $info->{group_name},
    );
    my $json = encode_json( \%request );
    print $sock $json;
    close $sock;
} ## end sub _send_notify_request

__PACKAGE__->meta->make_immutable;

1;
