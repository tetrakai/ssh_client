'''ssh-userauth and ssh-connection layer connection, for educational purposes only.

This module allows you to create an SSH connection to a remote server, logging all packets that are
sent between the two. It is very heavily dependent on the exact order of packets, and exact
algorithms sent by OpenSSH running on an Ubuntu 15.10 server.

Also note that this module requires that your private key not be password-protected. I recommend
creating a new, unencrypted keypair, for testing purposes, while using this module.

Example:
  To open a connection to the server `example.com`, and authenticate as the user `alice`, with the
  key stored in `~/.ssh/id_rsa`.

    import ssh_connection
    ssh = ssh_connection.SSHConnection('example.com', 'alice', '~/.ssh/id_rsa')
    ssh.connect()
    ssh.send('echo `whoami`\n')
    print ssh.read()
    ssh.disconnect()
'''

import colors

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA

from ssh_transport import SSHTransportConnection
from utils import parse_byte, generate_byte, \
                  parse_uint32, generate_uint32, \
                  parse_string, generate_string, \
                  generate_mpint, parse_name_list

SSH_MSG_NUMS = {
    'SSH_MSG_SERVICE_REQUEST': 5,
    'SSH_MSG_SERVICE_ACCEPT': 6,
    'SSH_MSG_USERAUTH_REQUEST': 50,
    'SSH_MSG_USERAUTH_FAILURE': 51,
    'SSH_MSG_USERAUTH_SUCCESS': 52,
    'SSH_MSG_GLOBAL_REQUEST': 80,
    'SSH_MSG_REQUEST_FAILURE': 82,
    'SSH_MSG_CHANNEL_OPEN': 90,
    'SSH_MSG_CHANNEL_OPEN_CONFIRMATION': 91,
    'SSH_MSG_CHANNEL_WINDOW_ADJUST': 93,
    'SSH_MSG_CHANNEL_DATA': 94,
    'SSH_MSG_CHANNEL_CLOSE': 97,
    'SSH_MSG_CHANNEL_REQUEST': 98,
    'SSH_MSG_CHANNEL_SUCCESS': 99,
}

SSH_USERAUTH_STRING = 'ssh-userauth'

class SSHConnection(object):
  '''An SSH connection - allows communication with a remote server over SSH.

  Args:
    hostname (string): The hostname of the server to communicate with.
    username (string): The username to be used for authentication.
    keyfile (string): The filename of the private key that will be used for authentication.

  Attributes:
    hostname (string): The hostname of the server to communicate with.
    username (string): The username of the server to communicate with.
    keyfile (string): The filename of the private key that will be used for authentication.
  '''

  def __init__(self, hostname, username, keyfile):
    self.username = username
    self.keyfile = keyfile

    self._ssh_transport_connection = SSHTransportConnection(hostname)

    # ssh-connection variables
    self._local_channel_number = 0
    self._remote_channel_number = None

  def connect(self):
    '''Open an authenticated connection to the remote server.'''

    self._ssh_transport_connection.connect()
    self._do_user_auth()
    self._create_ssh_connection()

  def disconnect(self):
    '''Cleanly close the connection to the remote server.'''

    # Send our exit status
    msg = []
    msg.append(generate_byte(SSH_MSG_NUMS['SSH_MSG_CHANNEL_REQUEST']))
    msg.append(generate_uint32(self._remote_channel_number))
    msg.append(generate_string('exit-status'))
    msg.append(generate_byte(0)) # False
    msg.append(generate_uint32(0)) # Exit status = 0
    self._ssh_transport_connection.send(''.join(msg))

    # Then close the channel
    msg = []
    msg.append(generate_byte(SSH_MSG_NUMS['SSH_MSG_CHANNEL_CLOSE']))
    msg.append(generate_uint32(self._remote_channel_number))
    self._ssh_transport_connection.send(''.join(msg))

    # Read back the remote side's exit status
    data = self._ssh_transport_connection.read()
    index, msg_type = parse_byte(data, 0)
    index, recipient_channel = parse_uint32(data, index)
    index, request_type = parse_string(data, index)
    index, want_reply_byte = parse_byte(data, index)
    want_reply = want_reply_byte != 0
    index, exit_status = parse_uint32(data, index)

    assert msg_type == SSH_MSG_NUMS['SSH_MSG_CHANNEL_REQUEST']
    assert recipient_channel == self._local_channel_number
    assert request_type == 'exit-status'
    assert not want_reply

    # Disconnect at the transport layer
    self._ssh_transport_connection.disconnect()

    return exit_status

  def read(self):
    '''Read data from the remote server.

    This data will be encrypted, and its authenticity guaranteed (both client-to-server and
    server-to-client).

    Returns (string): the data sent by the remote server.
    '''

    data = self._ssh_transport_connection.read()
    index, msg_type = parse_byte(data, 0)
    index, recipient_channel = parse_uint32(data, index)
    index, channel_data = parse_string(data, index)

    assert msg_type == SSH_MSG_NUMS['SSH_MSG_CHANNEL_DATA']
    assert recipient_channel == self._local_channel_number

    return channel_data

  def send(self, payload):
    '''Send data to the remote server.

    This data will be encrypted, and its authenticity guaranteed (both client-to-server and
    server-to-client).

    Args:
      payload (string): the data to be sent to the remote server.
    '''

    msg = []
    msg.append(generate_byte(SSH_MSG_NUMS['SSH_MSG_CHANNEL_DATA']))
    msg.append(generate_uint32(self._remote_channel_number))
    msg.append(generate_string(payload))
    self._ssh_transport_connection.send(''.join(msg))

  def _do_user_auth(self):
    # Ask the server whether it supports doing SSH user auth
    msg = []
    msg.append(generate_byte(SSH_MSG_NUMS['SSH_MSG_SERVICE_REQUEST']))
    msg.append(generate_string(SSH_USERAUTH_STRING))
    self._ssh_transport_connection.send(''.join(msg))

    # Check that it says yes
    data = self._ssh_transport_connection.read()
    index, msg_type = parse_byte(data, 0)
    assert msg_type == SSH_MSG_NUMS['SSH_MSG_SERVICE_ACCEPT'], \
      'Unknown message type received: %d' % msg_type
    index, service_name = parse_string(data, index)
    assert service_name == SSH_USERAUTH_STRING

    print colors.cyan("Let's do ssh-userauth!")

    # Ask the server which authentication methods it supports
    msg = []
    msg.append(generate_byte(SSH_MSG_NUMS['SSH_MSG_USERAUTH_REQUEST']))
    msg.append(generate_string(self.username.encode('utf-8')))
    msg.append(generate_string('ssh-connection'))
    msg.append(generate_string('none'))
    self._ssh_transport_connection.send(''.join(msg))

    # Check that publickey is one of them
    data = self._ssh_transport_connection.read()
    index, msg_type = parse_byte(data, 0)
    index, supported_auth_methods = parse_name_list(data, index)
    index, partial_success_byte = parse_byte(data, index)
    partial_success = partial_success_byte != 0

    assert msg_type == SSH_MSG_NUMS['SSH_MSG_USERAUTH_FAILURE'], \
      'Unknown message type: %d' % msg_type
    assert 'publickey' in supported_auth_methods, \
      'Server does not support public key authentication'
    assert not partial_success

    # Try to public key auth
    rsa_key = RSA.importKey(open(self.keyfile))
    pkcs_key = PKCS1_v1_5.new(rsa_key)

    msg = []
    msg.append(generate_byte(SSH_MSG_NUMS['SSH_MSG_USERAUTH_REQUEST']))
    msg.append(generate_string(self.username.encode('utf-8')))
    msg.append(generate_string('ssh-connection'))
    msg.append(generate_string('publickey'))
    msg.append(generate_byte(1)) # True: we really do want to authenticate
    msg.append(generate_string('ssh-rsa'))
    msg.append(generate_string(
        generate_string('ssh-rsa') + generate_mpint(rsa_key.e) + generate_mpint(rsa_key.n)
    ))

    # Desperately try to figure out how signing works in this silly encapsulating protocol
    signed_data = generate_string(self._ssh_transport_connection.session_id) + ''.join(msg)
    # OMG Pycrypto, did it have to be *your* SHA1 implementation?
    signature = pkcs_key.sign(SHA.new(signed_data))
    msg.append(generate_string(generate_string('ssh-rsa') + generate_string(signature)))

    # Send the public key auth message to the server
    self._ssh_transport_connection.send(''.join(msg))

    data = self._ssh_transport_connection.read()
    index, msg_type = parse_byte(data, 0)
    assert msg_type == SSH_MSG_NUMS['SSH_MSG_USERAUTH_SUCCESS'], \
      'Unknown message type: %d' % msg_type

    print colors.cyan('Successfully user authed!')

  def _create_ssh_connection(self):
    # Read the global request that SSH sends us - this is trying to let us know all host keys, but
    # it's OpenSSH-specific, and we don't need it
    data = self._ssh_transport_connection.read()
    index, msg_type = parse_byte(data, 0)
    index, request_name = parse_string(data, index)
    index, want_reply_byte = parse_byte(data, index)
    want_reply = want_reply_byte != 0

    assert msg_type == SSH_MSG_NUMS['SSH_MSG_GLOBAL_REQUEST']
    assert request_name == 'hostkeys-00@openssh.com'
    assert not want_reply

    # Reply to let OpenSSH know that we don't know what they're talking about
    msg = []
    msg.append(generate_byte(SSH_MSG_NUMS['SSH_MSG_REQUEST_FAILURE']))
    self._ssh_transport_connection.send(''.join(msg))

    # Actually get started with opening a channel for SSH communication
    window_size = 1048576
    maximum_packet_size = 16384

    # Request to open a session channel
    msg = []
    msg.append(generate_byte(SSH_MSG_NUMS['SSH_MSG_CHANNEL_OPEN']))
    msg.append(generate_string('session'))
    msg.append(generate_uint32(self._local_channel_number))
    msg.append(generate_uint32(window_size))
    msg.append(generate_uint32(maximum_packet_size))
    self._ssh_transport_connection.send(''.join(msg))

    # Check that a channel was opened successfully
    data = self._ssh_transport_connection.read()
    index, msg_type = parse_byte(data, 0)
    index, recipient_channel = parse_uint32(data, index)
    index, self._remote_channel_number = parse_uint32(data, index)
    index, initial_window_size = parse_uint32(data, index)
    index, maximum_packet_size = parse_uint32(data, index)

    print colors.cyan('Message type: %d' % msg_type)
    assert msg_type == SSH_MSG_NUMS['SSH_MSG_CHANNEL_OPEN_CONFIRMATION']
    assert recipient_channel == self._local_channel_number
    print colors.cyan('Remote channel number: %d' % self._remote_channel_number)
    print colors.cyan('Initial window size: %d' % initial_window_size)
    print colors.cyan('Maximum window size: %d' % maximum_packet_size)

    # Ask to turn that session channel into a shell
    msg = []
    msg.append(generate_byte(SSH_MSG_NUMS['SSH_MSG_CHANNEL_REQUEST']))
    msg.append(generate_uint32(self._remote_channel_number))
    msg.append(generate_string('shell'))
    msg.append(generate_byte(1)) # True, we do want a reply here
    self._ssh_transport_connection.send(''.join(msg))

    # OpenSSH then asks to increase their window size, that's fine, do it
    data = self._ssh_transport_connection.read()
    index, msg_type = parse_byte(data, 0)
    index, recipient_channel = parse_uint32(data, index)
    index, bytes_to_add = parse_uint32(data, index)
    assert msg_type == SSH_MSG_NUMS['SSH_MSG_CHANNEL_WINDOW_ADJUST']
    initial_window_size += bytes_to_add

    # Check that they tell us they've opened a channel successfully
    data = self._ssh_transport_connection.read()
    index, msg_type = parse_byte(data, 0)

    assert msg_type == SSH_MSG_NUMS['SSH_MSG_CHANNEL_SUCCESS']
    assert recipient_channel == self._local_channel_number

    print colors.cyan('Successfully opened shell!')
