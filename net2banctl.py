#!/usr/bin/env python
#
# Net2BanCtl
#
# Written by Chema Garcia (aka sch3m4)
#       chema@safetybits.net || http://safetybits.net
#       @sch3m4
#

import sys
sys.path.insert(1, "/usr/share/net2ban")

import os
import json
import time
import base64
import binascii
import ConfigParser
import net2ban
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto import Random

def get_client ( config ):
        client = sys.argv[2]
        if not config.has_section ( client ):
                print "Client not found: %s" % client
                return

        for item in ['global','keygen',client]:
                glob = config.options ( item )
                print "[%s]" % item
                for i in glob:
                        if i == 'mode':
                                print "mode = client"
                        else:
                                print "%s = %s" % (i , config.get ( item , i ) )
                print ""

def gen_random ( config ):
        len = int ( config.get ( 'keygen' , 'keylen' ) )
        return binascii.hexlify ( Random.new().read ( len / 2 ) )

def main():
        if len(sys.argv) < 2:
                print "Usage: %s COMMAND" % sys.argv[0]
                print "Commands available:"
                print "\tget_client client_name ------------> Get the config for the client client_name"
                print "\tupdate client_name /path/to/file --> Create/update the fail2ban actions file in all clients"
                print "\tlist_clients ----------------------> List all client names"
                print "\tgen_random ------------------------> Generate a random string to be used as client key or shared secret"
                print ""
                sys.exit(-1)

        n2b = net2ban.Net2Ban()

        config = ConfigParser.ConfigParser()
        config.read ( n2b.get_config_file() )

        if len(sys.argv) == 2 and sys.argv[1] == 'gen_random':
                print gen_random ( config )
                return

        if len(sys.argv) == 3 and sys.argv[1] == 'get_client':
                get_client ( config )
                return

        if len(sys.argv) == 2 and sys.argv[1] == 'list_clients':
                clients = config.sections()
                for c in ['global','server','keygen']:
                        if c in clients:
                                clients.remove(c)
                if len ( clients ) > 0:
                        print '\n'.join(clients)
                return

        if len(sys.argv) == 4 and sys.argv[1] == 'update':
                file = sys.argv[3]
                content = ''
                with open(file) as f:
                    for line in f:
                        line = line.split('#', 1)[0]
                        line = line.rstrip()
                        if len(line) > 0:
                                content += line + '\n'
                content = base64.b64encode ( content )
                file = ''.join(os.path.basename(sys.argv[3]).split('.')[:-1])
                data = { 'cmd': sys.argv[1] , 'file': file , 'content': content , 'client': sys.argv[2] }
        elif len(sys.argv) > 3 and sys.argv[1] == 'exec':
                data = { 'cmd': sys.argv[1] , 'file': sys.argv[2] , 'action': sys.argv[3]}
                vars = {}
                for v in sys.argv[4:]:
                        name = v.split('=')[0]
                        val = v.split('=')[1]
                        vars[name] = val
                data['params'] = vars
        else:
                print "Invalid parameters"
                return

        data['timestamp'] = time.time()
        msg = json.JSONEncoder().encode ( data )
        param = {}
        for i in ['server','rounds','secret','input','key','authkey']:
                section = None
                for j in ['server','global']:
                        if config.has_option ( j , i ):
                                section = j
                                break
                if section is None:
                        print "Cannot find '%s' value" % i
                        return
                param[i] = config.get ( section , i )

        client = net2ban.Client()
        client.set_parameters ( host = param['server'] , secret = param['secret'] , key = param['key'] , queue = param['input'] , rounds = param['rounds'] , auth_key = param['authkey'] )
        client.connect()

        key = client.get_session_key()
        iv = Random.new().read ( AES.block_size )
        cipher = AES.new ( key , AES.MODE_CBC , iv)
        total = len(msg)
        padlen = AES.block_size - ( total % AES.block_size )
        for i in range(0,padlen):
                msg += chr(padlen)
        encrypted = iv + cipher.encrypt ( msg )
        mhmac = hmac.new ( client.get_auth_key() , encrypted , hashlib.sha256 ).hexdigest()
        client.write ( encrypted + mhmac )
        client.disconnect()

if __name__ == "__main__":
        main()
