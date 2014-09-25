#!/usr/bin/env python
#
# Net2Ban
#
# Written by Chema Garcia (aka sch3m4)
#       chema@safetybits.net || http://safetybits.net
#       @sch3m4
#

import pika
import json
import time
import base64
import syslog
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
from passlib.hash import pbkdf2_sha256 as pbkdf2

class InvalidParams(Exception): pass

class Net2Ban(object):
        __VERSION = '0.0.2b'
        __SYSLOG_IDENT = 'net2ban'
        __LOCAL_PATH = '/usr/share/' + __SYSLOG_IDENT
        __ACTIONS_PATH = __LOCAL_PATH + '/actions'
        __CONFIG_FILE = __LOCAL_PATH + '/net2ban.cfg'

        def __init__ ( self , host = None , queue = None , valid_time = None ):
                self.host = host
                self.queue = queue
                self.vtime = valid_time

        def get_actions_path ( self ):
                return self.__ACTIONS_PATH

        def get_syslog_ident ( self ):
                return self.__SYSLOG_IDENT

        def get_config_file ( self ):
                return self.__CONFIG_FILE

        def get_version ( self ):
                return self.__VERSION

        def get_queue_name ( self ):
                return self.queue

        def get_valid_time ( self ):
                return self.vtime

        def connect ( self , queue = None ):
                """
                Connects to RabbitMQ server
                """
                self.connection = pika.BlockingConnection ( pika.ConnectionParameters ( self.host ) )
                self.channel = self.connection.channel()
                self.channel.queue_declare ( queue = self.queue , durable = True)

        def disconnect ( self ):
                """
                Disconnects from RabbitMQ server
                """
                self.connection.close()

        def write ( self , msg ):
                """
                Sends a message to the queue
                """
                self.channel.basic_publish ( exchange='' , routing_key = self.queue , body = msg , properties = pika.BasicProperties ( delivery_mode = 2 ) )

        def start_read ( self , func ):
                """
                Declares a callback function to receive messages
                NOTE: Don't forget to add "ch.basic_ack(delivery_tag = method.delivery_tag)" to your callback function
                TO CORRECTLY DECRYPT:
                """
                self.channel.queue_declare ( queue = self.queue , durable = True )
                self.channel.basic_qos ( prefetch_count = 1 )
                self.channel.basic_consume ( func , queue = self.queue )
                syslog.syslog ( syslog.LOG_INFO , "Started!" )
                self.channel.start_consuming()

        def get_session_key ( self ):
                return self.session_key

        def get_auth_key ( self ):
                return self.auth_key

        def decrypt ( self , msg ):
                iv = msg[:AES.block_size]
                mhmac = hmac.new ( self.get_auth_key() , msg[:-64] , hashlib.sha256 ).hexdigest()
                if msg[-64:] != mhmac:
                        return None
                msg = msg[:-64]
                cipher = AES.new ( self.session_key , AES.MODE_CBC , iv)
                decrypted = cipher.decrypt ( msg[AES.block_size:] )
                return decrypted[:-ord(decrypted[-1])]

        def parse_message ( self , msg ):
                try:
                        cfg = json.loads ( msg )
                        # basic keys
                        for i in ['timestamp','file','cmd']:
                                if not i in cfg.keys():
                                        raise InvalidParams

                        # specific keys
                        if cfg['cmd'] == 'exec' and ( not 'action' in cfg.keys() or not 'params' in cfg.keys() ):
                                raise InvalidParams
                        if cfg['cmd'] == 'update':
                                for i in ['content','file','client']:
                                        if not i in cfg.keys():
                                                raise InvalidParams
                                cfg['file'] = cfg['file'].replace('/','').replace('.','')
                except Exception,e:
                        syslog.syslog ( syslog.LOG_WARNING , "Malformed message: %s" % e )
                        return None

                # time verification
                if self.vtime is not None:
                        tval = time.time()
                        if tval < cfg['timestamp']:
                                syslog.syslog ( syslog.LOG_WARNING , "Message timestamp is in the future , discarding '%s:%s'" % ( cfg['command'] , cfg['ip'] ) )
                                return None

                        if self.vtime < int(tval - cfg['timestamp']):
                                syslog.syslog ( syslog.LOG_WARNING , "Message out of time, discarding '%s:%s'" % ( cfg['command'] , cfg['ip'] ) )
                                return None
                return cfg


class Client ( Net2Ban ):
        def set_parameters ( self , name = None , secret = None , host = None , queue = None , key = None , rounds = None , valid_time = None , auth_key = None):
                if None in [secret,host,queue,key,rounds,auth_key]:
                        raise InvalidParams
                super ( Client , self ).__init__ ( host , queue , valid_time )

                self.key = key
                self.auth_key = auth_key
                self.name = name
                self.secret = secret
                self.rounds = rounds
                self.session_key = pbkdf2.encrypt(key,salt=self.secret,rounds=int(self.rounds)).split('$')[4][:32]

        def get_name ( self ):
                return self.name


class Server ( Net2Ban ):
        def __init__ ( self ):
                self.clients = {}

        def set_parameters ( self , host = None , input = None , prefix = None , rounds = None , key = None , secret = None , valid_time = None , auth_key = None):
                if None in [host,prefix,input,auth_key]:
                        raise InvalidParams
                super ( Server , self ).__init__ ( host , input , valid_time )

                self.secret = secret
                self.key = key
                self.auth_key = auth_key
                self.rounds = rounds
                self.prefix = prefix
                self.session_key = pbkdf2.encrypt(key,salt=self.secret,rounds=int(self.rounds)).split('$')[4][:32]

        def add_client ( self , name = None , host = None , key = None , secret = None , rounds = None , valid_time = None , auth_key = None):
                if None in [host,name,key,secret,rounds,auth_key]:
                        raise InvalidParams
                self.clients[name] = Client()
                self.clients[name].set_parameters ( secret = secret , host = host , queue = self.prefix + name , key = key , rounds = rounds , valid_time = valid_time , name = name , auth_key = auth_key)
                self.clients[name].connect()

        def send_message ( self , msg , peer = None ):
                bmsg = msg
                for cli in self.clients.values():
                        if peer is not None and cli.get_name() != peer:
                                continue

                        msg = bmsg

                        key = cli.get_session_key()
                        iv = Random.new().read ( AES.block_size )
                        cipher = AES.new ( key , AES.MODE_CBC , iv)
                        # fix encryption padding
                        total = len(msg)
                        padlen = AES.block_size - ( total % AES.block_size )
                        for i in range(0,padlen):
                                msg += chr(padlen)
                        encrypted = iv + cipher.encrypt ( msg )
                        auth = hmac.new ( cli.get_auth_key() , encrypted , hashlib.sha256).hexdigest()
                        cli.write ( encrypted + auth )

        def shutdown ( self ):
                for cli in self.clients.values():
                        cli.disconnect()
                self.disconnect()
