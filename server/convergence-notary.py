#!/usr/bin/env python
"""convergence-notary implements the Convergence Notary System."""

__author__ = "Moxie Marlinspike"
__email__  = "moxie@thoughtcrime.org"
__license__= """
Copyright (c) 2010 Moxie Marlinspike <moxie@thoughtcrime.org>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License as
published by the Free Software Foundation; either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
USA

"""

import sys
if sys.version_info < (2, 6):
    print "Sorry, convergence requires at least Python 2.6"
    sys.exit(3)

# BSD and Mac OS X, kqueue
try:
    from twisted.internet import kqreactor as event_reactor
except:
    # Linux 2.6 and newer, epoll
    try:
        from twisted.internet import epollreactor as event_reactor
    except:
        # Linux pre-2.6, poll
        from twisted.internet import pollreactor as event_reactor

event_reactor.install()

from convergence.TargetPage import TargetPage
from convergence.ConnectChannel import ConnectChannel

from convergence.verifier.NetworkPerspectiveVerifier import NetworkPerspectiveVerifier
from convergence.verifier.GoogleCatalogVerifier import GoogleCatalogVerifier

from OpenSSL import SSL
from twisted.enterprise import adbapi
from twisted.web import http
from twisted.web.server import Site
from twisted.web.resource import Resource
from twisted.internet import reactor

import sys, string, os, getopt, logging, pwd, grp, convergence.daemonize
from opster import command

gVersion                  = "0.4"

class SSLContextFactory:

    def __init__(self, cert, key):
        self.cert         = cert
        self.key          = key

    def getContext(self):
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        ctx.use_certificate_chain_file(self.cert)
        ctx.use_privatekey_file(self.key)
        ctx.set_options(SSL.OP_NO_SSLv2)

        return ctx

def usage():
    print "\nnotary " + str(gVersion) + " by Moxie Marlinspike"
    print "usage: notary <options>\n"
    print "Options:"
    print "-p <http_port> HTTP port to listen on (default 80)."
    print "-s <ssl_port>  SSL port to listen on (default 443)."
    print "-i <address>   IP address to listen on for incoming connections (optional)."
    print "-c <cert>      SSL certificate location."
    print "-k <key>       SSL private key location."
    print "-u <username>  Name of user to drop privileges to (defaults to 'nobody')"
    print "-g <group>     Name of group to drop privileges to (defaults to 'nogroup')"
    print "-b <backend>   Verifier backend [perspective|google] (defaults to 'perspective')"
    print "-f             Run in foreground."
    print "-d             Debug mode."
    print "-h             Print this help message."
    print ""

def initializeBackend(backend):
    if   (backend == "perspective"): return NetworkPerspectiveVerifier()
    elif (backend == "google"):      return GoogleCatalogVerifier()
    else:                            raise getopt.GetoptError("Invalid backend: " + backend)
    
def checkPrivileges(userName, groupName):                
    try:
        grp.getgrnam(groupName)
    except KeyError:
        print >> sys.stderr, 'Can not drop group privileges to %s, ' \
              'because it does not exist!' % groupName
        sys.exit(2)

    try:
        pwd.getpwnam(userName)
    except KeyError:
        print >> sys.stderr, 'Can not drop user privilges to %s, ' \
              'because it does not exist!' % userName
        sys.exit(2)            

def writePidFile(pid_file):
    pidFile = open(pid_file, "wb")
    pidFile.write(str(os.getpid()))
    pidFile.close()
    
def dropPrivileges(userName, groupName, database_path):
    if os.environ.get('LOGNAME') != 'root':
        return

    try:
        user = pwd.getpwnam(userName)
    except KeyError:
        print >> sys.stderr, 'User ' + userName + ' does not exist, cannot drop privileges'
        sys.exit(2)
    try:
        group = grp.getgrnam(groupName)
    except KeyError:
        print >> sys.stderr, 'Group ' + groupName + ' does not exist, cannot drop privileges'
        sys.exit(2)

    os.chown(os.path.dirname(database_path), user.pw_uid, group.gr_gid)
    os.chown(database_path, user.pw_uid, group.gr_gid)
    
    os.setgroups([group.gr_gid])
    os.setgid(group.gr_gid)
    os.setuid(user.pw_uid)

def initializeLogging(logFilename, logLevel):
    logging.basicConfig(filename=logFilename,level=logLevel, 
                        format='%(asctime)s %(message)s',filemode='a')        

    logging.info("Convergence Notary started...")

def initializeFactory(database, privateKey, verifier):
    root = Resource()
    root.putChild("target", TargetPage(database, privateKey, verifier))

    return Site(root)    

def initializeDatabase(database_path):
    return adbapi.ConnectionPool("sqlite3", database_path, cp_max=1, cp_min=1)

def initializeKey(keyFile):
    return open(keyFile,'r').read() 

@command()
def main(
        log_file=('l', '/var/log/convergence.log', 'filename to log to'),
        debug=('d', False, 'verbose output'),
        http_port=('p', 80, 'http port'),
        proxy_port=('', 4242, 'proxy port'),
        ssl_port=('s', 443, 'ssl port'),
        interface=('i', '', 'incoming interface'),
        cert=('c', '/etc/ssl/certs/convergence.pem', 'path to public certificate key'),
        key=('k', '/etc/ssl/private/convergence.key', 'path to private key'),
        uname=('u', 'nobody', 'user name to drop privileges'),
        gname=('g', 'nogroup', 'user name to drop privileges'),
        foreground=('f', False, 'run server in foreground'),
        backend=('b', '', 'verifier backend (optional)'),
        db_path=('', '/var/lib/convergence/convergence.db', 'database path'),
        pid_file=('', '/var/run/convergence.pid', 'pid file'),
        no_https=('', False, 'turn off ssl on listened ports (useful to put Twisted behind Nginx)'),
    ):


    loglevel = logging.INFO
    if debug:
        loglevel = logging.DEBUG

    verifier = NetworkPerspectiveVerifier()
    if backend:
        verifier = initializeBackend(backend)

    privateKey                    = initializeKey(key)
    database                      = initializeDatabase(db_path)
    notaryFactory                    = initializeFactory(database, privateKey, verifier)
    proxyConnectFactory                = http.HTTPFactory(timeout=10)
    proxyConnectFactory.protocol       = ConnectChannel

    if no_https:
        reactor.listenTCP(ssl_port, notaryFactory,
                          interface=interface)
        reactor.listenTCP(proxy_port, notaryFactory,
                          interface=interface)
    else:
        reactor.listenSSL(ssl_port, notaryFactory, SSLContextFactory(cert, key),
                          interface=interface)
        reactor.listenSSL(proxy_port, notaryFactory, SSLContextFactory(cert, key),
                          interface=interface)

    reactor.listenTCP(port=http_port, factory=proxyConnectFactory,
                      interface=interface)

    initializeLogging(log_file, loglevel)
    checkPrivileges(uname, gname)

    if foreground:
        print "\nconvergence " + str(gVersion) + " by Moxie Marlinspike running..."
    else:
        print "\nconvergence " + str(gVersion) + " by Moxie Marlinspike backgrounding..."
        convergence.daemonize.createDaemon()

    writePidFile(pid_file)
    dropPrivileges(uname, gname, db_path)

    reactor.run()

if __name__ == '__main__':
    main.command()
