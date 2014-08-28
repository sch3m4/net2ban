The problem
-----------
Imagine a common scenario in which you have to manage multiple servers and all those servers send its logs to a remote centralized syslog server. In this scenario may that be even the final servers do not store its logs locally unless a network connection problem occurs.

So you have a centralized syslog server in which you store (among others) all detected break-in attempts, brute force attacks, etc. The next question is, once you have detected a break-in attempt or a brute force attack in one of your servers, how can you remotely ban the attacker IP in that server and in the other ones?

The first response: Fail2Ban
----------------------------
Fail2Ban is a great and very powerful tool, but it is designed to work locally, what turns it  in a nightmare when trying to use it in our scenario. Even if the logs were stored locally, you still have to manage the fail2ban filters and actions in all servers, although this approach could be solved by using some kind of shared storage, etc.

The good response: Net2Ban
--------------------------
Since I did not found any open source project to manage the given approach, I decided to write my own solution, here is where net2ban comes in rescue.

What is Net2Ban?
----------------
As you can guess, Net2Ban is inspired in fail2ban, but it is much more simple and flexible. It has two *main* parts: Server, and client. Aditionaly it uses RabbitMQ as message brooker to communicate from server to clients, and has a tool to send commands to the server in order to propagate the actions.

Security
--------
For each communication between nodes, net2ban uses AES256 encryption in CBC mode, PBKDF2 to generate the session key and HMAC-SHA256, in order to protect and guarantee the integrity,confidentiality and authenticity of each message. The parameters to set up the encryption schema will be explained in the next points.


Workflow
------------
To identify the difference between fail2ban and net2ban, and understand how they can be mixed, here is a simple schema representing the workflow of both tools:

Fail2Ban:
<dl><pre>
                            --> filters ->-
                          2 |             |
  ##############   1    ########################   3    ###########
  # LOG SOURCE # -----> # Fail2Ban (Detection) # -----> # Actions #
  ##############        ########################        ###########
</pre></dl>


Net2Ban:
<dl><pre>
                           --> intelligence ->-
                         2 |                  |
                        ########################
  ##############   1    #   DETECTION AND/OR   #   3    ###########   
  # LOG SOURCE # -----> #  CORRELATION ENGINE  # -----> # ACTIONS # ---
  ##############        ########################        ###########   | 4
                                                                      |
   -------------------------------------------------------------------|
   |
 4 |    ###############################   5    ###################
   |--> # Net2Ban: DO 'X' ACTION WITH # -----> # RABBITMQ SERVER # --
        # 'Y' IP AND 'Z' PORT(S)      #        ###################  |
        ###############################                             | 6
                                                                    |
  ------------------------------------------------------------------|
  |
6 |    ############################
  |    # NET2BAN SERVER: FORWARDS #   7    ###################################
  |--> # THE MESSAGE TO THE NODES # -----> # NET2BAN CLIENT: DOES 'X' ACTION #
       # THROUGH RABBITMQ         #        # WITH 'Y' IP AND 'Z' PORT(S)     #
       ############################        ###################################
</pre></dl>


Why RabbitMQ?
-------------
It is true that there are many message brokers such as reddit or activemq, some of them give you a higher performance level when dealing in big environments such as WANs, but in my case, there was a RabbitMQ server already installed in the network. On the other hand, net2ban can be modified to work with a message broker specified in the configuration file. This approach could be made in future versions...

Installation
============

##### Common Tasks
The following tasks are commons and required to install net2ban in the servers as well as in the clients:

<dl><pre>
apt-get install python-pika python-passlib python-crypto
git clone https://github.com/sch3m4/net2ban.git net2ban
cd net2ban
mkdir -p /user/share/net2ban/actions
useradd -r -M net2ban -s /bin/false -b /usr/share
cp -r net2ban /usr/share/net2ban/
cp net2ban.py /usr/share/net2ban/
cp net2ban.cfg /usr/share/net2ban/
cp net2ban_init.d /etc/init.d/net2ban
chown root:root /etc/init.d/net2ban
chmod 0750 /etc/init.d/net2ban
update-rc.d net2ban defaults
</pre></dl>

##### Server
Some extra actions to be made on server side:
<dl><pre>
apt-get install rabbitmq-server fail2ban
service fail2ban stop
cp net2ban.cfg /usr/share/net2ban/
cp net2banctl.py /sbin/net2banctl
chown root:root /sbin/net2banctl
chmod 0750 /sbin/net2banctl
</pre></dl>

##### Client
Some extra actions to be made on client side:
<dl><pre>
apt-get install sudoers
</pre></dl>

In order to allow net2ban user execute the iptables binary, add the following entry to your "/etc/sudoers" file:
<dl><pre>
echo 'net2ban ALL=NOPASSWD: /sbin/iptables' >> /etc/sudoers
</pre></dl>

NOTE: Add an entry like the aforementioned for each privileged command susceptible of being executed by net2ban clients

##### Final common steps
As final steps, don't forget to change the owner and permissions of net2ban files:

<dl><pre>
chown -R net2ban:net2ban /usr/share/net2ban
chmod -R 0750 /usr/share/net2ban
</pre></dl>

Configuration schema
====================

The net2ban.cfg looks as follows:
<dl><pre>
[global]
server = 172.16.0.1
rounds = 12000
secret = 57bae6f17927fee0309cd0fcf900903d0bf49277
mode = server
valid_wtime = 3600
authkey = fe64809ba0286c72123d15ffb3554f261ef835d0
queue_prefix = net2ban_

[server]
input = input_net2ban
key = 1e3648858a30a105374c1a8a7f05e4fc0dff2abc

[keygen]
keylen = 40

[client1]
key = key1
</pre></dl>

##### global
The options in this sections are used by the server and clients. It can be used to set some parameters to a default value.
###### server
This is the host/ip of the RabbitMQ server, used to establish the communication between the server and clients.
###### mode
This is the working mode of this instance of net2ban, and have to be set to "client" or "server".
###### valid_wtime
Valid window time for the messages, in seconds. All those messages that have been sent before the relative "valid_wtime" will be discarted.
###### rounds
Rounds to be used when generating the session key by using PBKDF2
###### secret
Shared secret to be used with the key of each client, to generate the session key by using PBKDF"
###### authkey
Authentication key to generate the HMAC-SHA256 of each message
###### queue_prefix
Prefix to create a queue for each client

##### server
This section is specific to the server side.
###### input
Queue name to read the messages and forward them
###### key
Key used to decrypt the messages received

##### keygen
###### keylen
When generating random keys to be used as auth key/secret/key through net2banctl, this parameter set the length of the generated random string

##### client1
The name of this section is arbitrary and should not match with other entries. The name of this section will be used as client's name.
###### key
Key used to decrypt the messages received

#### Specifying individual parameters
The above configuration schema is the minimum required, as it can be modified by adding some parameters to server and clients sections in order to override the default ones.
On this point, you can add the following options to any section related to clients/server:
..* rounds
..* secret
..* key
..* valid_wtime
..* authkey

Referring to the cryptographic values, the only key that must be similar in server and client side, is the "secret" option. If you locally modify a key on client side, remember to set the same key in the section belonging to that client in net2ban.cfg on server side.

Sample configuration
====================
On this point we're going to generate a configuration file to use the RabbitMQ server on 172.16.15.2 using two clients: client1 and client2. Moreover we will use individual configurations for the clients.

## Server side
At this step we are going to modify the net2ban.cfg file to set the proper values in order to work on server side, and afterwards copy the configuration to the clients.

The minimum required configuraton looks as follows:
<dl><pre>
[global]
server = 172.16.15.2
rounds = 12000
secret = 57bae6f17927fee0309cd0fcf900903d0bf49277
mode = server
valid_wtime = 3600
authkey = fe64809ba0286c72123d15ffb3554f261ef835d0
queue_prefix = net2ban_

[server]
input = input_net2ban
key = 1e3648858a30a105374c1a8a7f05e4fc0dff2abc

[keygen]
keylen = 40

[client1]
key = key1

[client2]
key = key2
</pre></dl>

To generate the client keys, we will use net2banctl:
<dl><pre>
$ for i in $(seq 1 2); do net2banctl gen_random ; done
ca82cd669623f6434e02eecade0236b50fc18cb3
767c138a4483e692f41af3d1491f06c0ead41b5b
$
</pre></dl>

Now, set the 'key' clients option to these values:

<dl><pre>
[client1]
key = ca82cd669623f6434e02eecade0236b50fc18cb3

[client2]
key = 767c138a4483e692f41af3d1491f06c0ead41b5b
</pre></dl>

If you want some client to use a different value of "rounds", just specify it in his section:

<dl><pre>
[client2]
rounds = 100
key = 767c138a4483e692f41af3d1491f06c0ead41b5b
</pre></dl>

## Client side
Indeed the client configuration is almost done. On this step you still need access to the server.

To verify that net2banctl can see the configuration file and the clients specified on it, execute:
<dl><pre>
$ net2banctl list_clients
client1
client2
</pre></dl>

Now, we need to export the configuration of each client and save it in /usr/share/net2ban/net2ban.cfg on each client. To do that, execute the following on the server:
<dl><pre>
$ net2banctl get_client client1 > client1.cfg
$ cat client1.cfg
[global]
server = 172.16.15.2
rounds = 12000
secret = 57bae6f17927fee0309cd0fcf900903d0bf49277
mode = client
valid_wtime = 3600
authkey = fe64809ba0286c72123d15ffb3554f261ef835d0
queue_prefix = net2ban_

[keygen]
keylen = 40

[client1]
key = ca82cd669623f6434e02eecade0236b50fc18cb3
$
</pre></dl>

## Integrating net2ban & fail2ban
In order to use net2ban in conjunction with fail2ban, you need to do some changes to your fail2ban configuration. First of all, copy your fail2ban action file (defined in /etc/fail2ban/jail.conf, [DEFAULT]/banaction) to /usr/share/net2ban/actions. In my case, I'm using "iptables-multiport":

<dl><pre>
$ cp /etc/fail2ban/actions.d/iptables-multiport.conf /usr/share/net2ban/actions/
</pre></dl>

Edit the original fail2ban action file (in my case: /etc/fail2ban/actions.d/iptables-multiport.conf) and modify the value of the defined actions to the following ones:

<dl><pre>
[Definition]
actionstart = net2banctl exec iptables-multiport actionstart name=&lt;name&gt; chain=&lt;chain&gt; protocol=&lt;protocol&gt; port=&lt;port&gt;
actionstop = net2banctl exec iptables-multiport actionstop name=&lt;name&gt; chain=&lt;chain&gt; protocol=&lt;protocol&gt; port=&lt;port&gt;
actionban = net2banctl exec iptables-multiport actionban name=&lt;name&gt; ip=&lt;ip&gt;
actionunban = net2banctl exec iptables-multiport actionunban name=&lt;name&gt; ip=&lt;ip&gt;
# cheats fail2ban
actioncheck = echo -n "&lt;chain&gt;&lt;name&gt;" && exit 0

[Init]
name = default
port = ssh
protocol = tcp
chain = INPUT
</pre></dl>

We're almost done. The final step is to start the net2ban daemon in server and clients side and send the "actions" file to the clients:

<dl><pre>
$ for i in $(net2banctl list_clients); do net2banctl update $i /usr/share/net2ban/actions/iptables-multiport.conf ; done
$
</pre></dl>

IMPORTANT: Remember to modify the actions file and add "sudo" before "iptables" to execute each command as root.

Personally I prefer to ban the IP without taking care about the port, so the given IP is globally banned, here is my "iptables-multiport.conf" actions file:

<dl><pre>
[Definition]
actionstart = sudo iptables -N fail2ban-<name>
              sudo iptables -A fail2ban-<name> -j RETURN
              sudo iptables -I <chain> -p <protocol> -j fail2ban-<name>
actionstop = sudo iptables -D <chain> -p <protocol> -j fail2ban-<name>
             sudo iptables -F fail2ban-<name>
             sudo iptables -X fail2ban-<name>
actionban = sudo iptables -I fail2ban-<name> 1 -s <ip> -j DROP
actionunban = sudo iptables -D fail2ban-<name> -s <ip> -j DROP
[Init]
name = default
port = ssh
protocol = tcp
chain = INPUT
</pre></dl>

After that you should see something like this in your syslog:

<dl><pre>
........ net2ban: File "iptables-multiport" updated
</pre></dl>


Not restricted to Fail2Ban
--------------------------
net2ban is not only restricted to be used with fail2ban, due to its architecture it can be used with any software. Imagine the following scenario:

..* User 'user1' log in into a corporate application
..* User 'user1' has not loged in his workstation

The correlation engine detects an abnormal behaviour and executes net2banctl to automatically ban the IP on the other servers and/or applications (keep in mind that you are not limited to execute the iptables binary on client side) and report it.

Saving net2ban server logs
--------------------------
By default, net2ban uses syslog to send logs, so if you want to save the logs generated by the tool in a different file (by default is logs to "daemon" file) you can modify your syslog-ng rules and add the following lines:

<dl><pre>destination d_net2ban { file ( "/var/log/net2ban.log" ); };
destination d_rnet2ban { file ( "/var/log/remote/$FULLHOSTNAME/net2ban.log" );
filter f_net2ban { facility ( daemon ); program ( "net2ban" ); };
log { source(s_src); filter(f_net2ban); destination(d_net2ban); flags ( final ); };
log { source(s_udp); filter(f_net2ban); destination(d_rnet2ban); flags ( final ); };</pre></dl></pre></dl>

Keep in mind that the "log" rules must be the first matching rules in order to avoid duplicate logs.

Sample output
-------------
Whenever fail2ban detects a break-in attept, it will generate an entry in the log like this:

<dl><pre>.... fail2ban.actions: WARNING [dovecot] Ban 95.48.84.XXX</pre></db>

That action will execute net2banctl and send the message to the server, and the following log entry will be generated in your server:

<dl><pre>..... net2ban: Forwarding: exec/iptables-multiport</pre></db>

Finally, the net2ban nodes will receive the message, send a log entry and execute the action:

<dl><pre>..... net2ban: IP 95.48.84.XXX banned</pre></db>

<dl><pre>$ iptables -nvL | grep -i 95.48.84.XXX
    9   564 DROP       all  --  *      *       95.48.84.XXX         0.0.0.0/0
$</pre></db>

Considerations
==============
net2ban uses persistent queues on RabbitMQ, if a client is not connected and the server sends five messages to that client, the messages are stored in the queue, waiting for the client to connect and read them.
On that point is very important the parameter "valid_wtime" in order to discard old messages.
Even in a normal behaviour, and due to the parameter "valid_wtime" is very important that all nodes to be synchronized (ex: by using NTP)

Code issues
===========
The code is *very dirty*, it's a program written very fast "to work right now"...
