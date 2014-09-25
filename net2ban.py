#!/usr/bin/env python
#
# Net2Ban
#
# Written by Chema Garcia (aka sch3m4)
#       chema@safetybits.net || http://safetybits.net
#       @sch3m4
#

import sys
sys.path.insert(1, "/usr/lib/python2.7/dist-packages")
sys.path.insert(1, "/usr/share/net2ban")

import os
import net2ban
import base64
import signal
import syslog
import ConfigParser

MODE = None

n2b = net2ban.Net2Ban()
client = net2ban.Client()
server = net2ban.Server()

def exit_net2ban ( code , frame = None ):
        if client is not None:
                try:
                        client.disconnect()
                except:
                        pass

        if server is not None:
                try:
                        server.shutdown()
                except:
                        pass

        syslog.syslog ( syslog.LOG_CRIT , 'Exiting...' )
        sys.exit ( code )


def client_callback(ch, method, properties, body):
        ch.basic_ack(delivery_tag = method.delivery_tag)

        try:
                msg = client.decrypt ( body )
        except Exception,e:
                syslog.syslog ( syslog.LOG_WARNING , "Cannot decrypt message: %s" % e )
                return

        cfg = client.parse_message ( msg )
        if cfg is None:
                return

        if cfg['cmd'] == 'update':
                try:
                        f = open ( n2b.get_actions_path() + '/' + cfg['file'] + '.conf' , 'w' )
                        content = base64.b64decode ( cfg['content'] )
                        f.write ( content )
                        f.close()
                        syslog.syslog ( syslog.LOG_WARNING , "File \"%s\" updated" % cfg['file'] )
                except Exception,e:
                        syslog.syslog ( syslog.LOG_WARNING , "Cannot update file \"%s\": %s" % ( cfg['file'] , e ) )
                return

        if cfg['cmd'] == 'exec':
                path = n2b.get_actions_path() + '/' + cfg['file'] + '.conf'
                action = ConfigParser.ConfigParser()
                action.read ( path )
                if not 'Definition' in action.sections() or action.has_option ( 'Definition' , cfg['action'] ) is False:
                        syslog.syslog ( syslog.LOG_WARNING , "Corrupt file \"%s.conf\"" % cfg['file'] )
                        return
                command = action.get ( 'Definition' , cfg['action'] )
                for c in command.split('\n'):
                        for p in cfg['params'].keys():
                                c = c.replace ( '<' + p + '>' , cfg['params'][p] ).replace ('\r','')
                        os.system ( c )
                        if cfg['action'] == 'actionban':
                                syslog.syslog ( syslog.LOG_WARNING , "IP %s banned" % cfg['params']['ip'] )
                        elif cfg['action'] == 'actionunban':
                                syslog.syslog ( syslog.LOG_WARNING , "IP %s unbanned" % cfg['params']['ip'] )
                        elif cfg['action'] == 'actionstart':
                                syslog.syslog ( syslog.LOG_WARNING , "Seting up..." )
                        elif cfg['action'] == 'actionstop':
                                syslog.syslog ( syslog.LOG_WARNING , "Stopping..." )


def server_callback(ch, method, properties, body):
        ch.basic_ack(delivery_tag = method.delivery_tag)

        try:
                msg = server.decrypt ( body )
        except Exception,e:
                syslog.syslog ( syslog.LOG_WARNING , "Cannot decrypt message: %s" % e )
                return

        if msg is None:
                syslog.syslog ( syslog.LOG_WARNING , "Invalid HMAC: Message dropped" )
                return

        cfg = server.parse_message ( msg )
        if cfg is None:
                return

        syslog.syslog ( syslog.LOG_INFO , "Forwarding: %s/%s" % ( cfg['cmd'] , cfg['file'] ) )
        server.send_message ( msg )


def main():
        config = ConfigParser.ConfigParser()
        config.read ( n2b.get_config_file() )

        cfgserver = config.get ( 'global' , 'server' )
        cfgrounds = config.get ( 'global' , 'rounds' )
        cfgtime = config.get ( 'global' , 'valid_wtime' )
        cfgsecret = config.get ( 'global' , 'secret' )
        cfgauthk = config.get ( 'global' , 'authkey' )
        MODE = config.get ( 'global' , 'mode' ).lower()
        cfgprefix = config.get ( 'global' , 'queue_prefix' ).lower()

        clients = config.sections()
        try:
                clients.remove('server')
        except:
                pass
        clients.remove('global')
        if 'keygen' in clients:
                clients.remove('keygen')

        # working on server mode
        if MODE == 'server':
                syslog.syslog ( syslog.LOG_INFO , 'Working in server mode' )
                cfginput = config.get ( 'server' , 'input' ).lower()
                cfgservkey = config.get ( 'server' , 'key' )
                if config.has_option ( 'server' , 'rounds' ):
                        cfgrounds = config.get ( 'server' , 'rounds' )
                if config.has_option ( 'server' , 'secret' ):
                        cfgsecret = config.get ( 'server' , 'secret' )
                if config.has_option ( 'server' , 'valid_wtime' ):
                        cfgtime = config.get ( 'server' , 'valid_wtime' )
                if config.has_option ( 'server' , 'authkey' ):
                        cfgauthk = config.get ( 'server' , 'authkey' )
                server.set_parameters ( host = cfgserver , prefix = cfgprefix , input = cfginput , rounds = cfgrounds , key = cfgservkey , secret = cfgsecret , valid_time = cfgtime , auth_key = cfgauthk )
                server.connect()
                syslog.syslog ( syslog.LOG_INFO , 'Server loaded' )

                # adds each client to the clients pool of the server
                for cli in clients:
                        specific = False
                        cfgkey = config.get ( cli , 'key' )
                        if config.has_option ( cli , 'secret' ):
                                cfgsecret = config.get ( cli , 'secret' )
                        if config.has_option ( cli , 'rounds' ):
                                cfgrounds = config.get ( cli , 'rounds' )
                        if config.has_option ( cli , 'valid_wtime' ):
                                cfgtime = config.get ( cli , 'valid_wtime' )
                        if config.has_option ( cli , 'authkey' ):
                                cfgauthk = config.get ( cli , 'authkey' )

                        server.add_client ( cli , cfgserver , cfgkey , cfgsecret , cfgrounds , cfgtime , cfgauthk )
                        syslog.syslog ( syslog.LOG_INFO , "Client added: %s" % cli )

        # working on client mode
        else:
                syslog.syslog ( syslog.LOG_INFO , 'Working in client mode' )
                if len(clients) > 1:
                        syslog.syslog ( syslog.CRITICAL , 'Too many client definitions in the configuration file' )
                        exit_net2ban ( -1 )

                cfgname = clients[0]
                if config.has_option ( cfgname , 'server' ):
                        cfgserver = config.get ( client , 'server' )
                cfgkey = config.get ( cfgname , 'key' )
                if config.has_option ( cfgname , 'secret' ):
                        cfgsecret = config.get ( cfgname , 'secret' )
                if config.has_option ( cfgname , 'rounds' ):
                        cfgrounds = config.get ( cfgname , 'rounds' )
                if config.has_option ( cfgname , 'valid_wtime' ):
                        cfgtime = config.get ( cfgname , 'valid_wtime' )
                if config.has_option ( cfgname , 'authkey' ):
                        cfgauthk = config.get ( cfgname , 'authkey' )
                client.set_parameters ( host = cfgserver , secret = cfgsecret , key = cfgkey , queue = cfgprefix + cfgname , rounds = cfgrounds , valid_time = cfgtime , name = cfgname , auth_key = cfgauthk )
                client.connect()
                syslog.syslog ( syslog.LOG_INFO , 'Client loaded' )

        if MODE == 'server':
                server.start_read ( server_callback )
        else:
                client.start_read ( client_callback )

if __name__ == "__main__":
        signal.signal ( signal.SIGINT, exit_net2ban )
        signal.signal ( signal.SIGTERM, exit_net2ban )

        syslog.openlog ( ident = n2b.get_syslog_ident() , facility = syslog.LOG_DAEMON )
        syslog.syslog ( syslog.LOG_INFO , "net2ban %s started. Reading configuration file: %s" % ( n2b.get_version() , n2b.get_config_file() ) )

        while True:
                try:
                        main()
                except Exception,e:
                        syslog.syslog ( syslog.LOG_WARNING , "Error detected, restarting fail2ban: %s" % e )
