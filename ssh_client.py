
# Disable Pylint warnings about bad variable names - many of the names specified in the RFC are
# either too short (e.g. r, s in Diffie Hellman), or too long
# (e.g. encryption_algorithms_client_to_server)
# pylint: disable=invalid-name

import hashlib
import hmac
import os
import random
import re
import socket
import sys

import colors
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
import ecdsa
import ecdsa.util

from ssh_utils import parse_byte, generate_byte, \
                      parse_uint32, generate_uint32, \
                      parse_string, generate_string, \
                      parse_name_list, generate_name_list, \
                      parse_mpint, generate_mpint, \
                      random_bytes, get_32_byte_repr

SSH_PORT = 22
SSH_MSG_NUMS = {
    'SSH_MSG_DISCONNECT': 1,
    'SSH_MSG_IGNORE': 2,
    'SSH_MSG_UNIMPLEMENTED': 3,
    'SSH_MSG_DEBUG': 4,
    'SSH_MSG_SERVICE_REQUEST': 5,
    'SSH_MSG_SERVICE_ACCEPT': 6,
    'SSH_MSG_KEXINIT': 20,
    'SSH_MSG_NEWKEYS': 21,
    'SSH_MSG_KEXDH_INIT': 30,
    'SSH_MSG_KEXDH_REPLY': 31,
    'SSH_MSG_USERAUTH_REQUEST': 50,
    'SSH_MSG_USERAUTH_FAILURE': 51,
    'SSH_MSG_USERAUTH_SUCCESS': 52,
    'SSH_MSG_USERAUTH_BANNER': 53,
    'SSH_MSG_USERAUTH_PK_OK': 60,
    'SSH_MSG_GLOBAL_REQUEST': 80,
    'SSH_MSG_REQUEST_SUCCESS': 81,
    'SSH_MSG_REQUEST_FAILURE': 82,
    'SSH_MSG_CHANNEL_OPEN': 90,
    'SSH_MSG_CHANNEL_OPEN_CONFIRMATION': 91,
    'SSH_MSG_CHANNEL_OPEN_FAILURE': 92,
    'SSH_MSG_CHANNEL_WINDOW_ADJUST': 93,
    'SSH_MSG_CHANNEL_DATA': 94,
    'SSH_MSG_CHANNEL_EXTENDED_DATA': 95,
    'SSH_MSG_CHANNEL_EOF': 96,
    'SSH_MSG_CHANNEL_CLOSE': 97,
    'SSH_MSG_CHANNEL_REQUEST': 98,
    'SSH_MSG_CHANNEL_SUCCESS': 99,
    'SSH_MSG_CHANNEL_FAILURE': 100,
}

COOKIE_LEN = 16
KEX_RESERVED_BYTES_LEN = 4
AES_BLOCK_LEN = 16
SHA1_LEN = 20
MIN_PADDING_LEN = 4
KEX_ALGORITHM = 'diffie-hellman-group14-sha1'
SERVER_HOST_KEY_ALGORITHM = 'ecdsa-sha2-nistp256'
ENCRYPTION_ALGORITHM = 'aes128-ctr'
MAC_ALGORITHM = 'hmac-sha1'
COMPRESSION_ALGORITHM = 'none'
SSH_USERAUTH_STRING = 'ssh-userauth'

def main(argv):
  username, hostname = argv[1].split('@')
  keyfile = argv[2]

  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.connect((hostname, SSH_PORT))
  ssh = SSHConnection(sock, hostname, username, keyfile)
  ssh.connect()

  print colors.red(ssh.read())
  while True:
    try:
      command_to_run = raw_input('> ')
    except EOFError:
      command_to_run = ''

    if command_to_run.strip() == '':
      break
    ssh.send(command_to_run + '\n')
    print colors.red(ssh.read())

  exit_status = ssh.disconnect()
  sock.close()

  return exit_status

class SSHConnection(object):
  '''An SSH connection - allows communication with a remote server over SSH.

  Args:
    sock (socket): The socket to communicate over.
    hostname (string): The hostname of the server to communicate with.
    username (string): The username to be used for authentication.
    keyfile (string): The filename of the private key that will be used for authentication.

  Attributes:
    hostname (string): The hostname of the server to communicate with.
    username (string): The username of the server to communicate with.
    keyfile (string): The filename of the private key that will be used for authentication.
  '''

  def __init__(self, sock, hostname, username, keyfile):
    # Initial setup variables
    self.hostname = hostname
    self.username = username
    self.keyfile = keyfile
    self._client_id_string = 'SSH-2.0-karlassh\r\n'
    self._server_id_string = ''

    # Whole session variables
    self._socket = sock
    self._session_id = None
    self._packets_received_counter = 0
    self._packets_sent_counter = 0
    self._aes_client_to_server = None
    self._aes_server_to_client = None
    self._integrity_key_client_to_server = None
    self._integrity_key_server_to_client = None

    # ssh-connection variables
    self._local_channel_number = None
    self._remote_channel_number = None

  def connect(self):
    self._send_and_receive_id_strings()
    self._do_key_exchange()
    self._do_user_auth()
    self._create_ssh_connection()

  def read(self):
    data = self._read_packet()
    index, msg_type = parse_byte(data, 0)
    index, recipient_channel = parse_uint32(data, index)
    index, channel_data = parse_string(data, index)

    assert msg_type == SSH_MSG_NUMS['SSH_MSG_CHANNEL_DATA']
    assert recipient_channel == self._local_channel_number

    return channel_data

  def send(self, to_send):
    msg = []
    msg.append(generate_byte(SSH_MSG_NUMS['SSH_MSG_CHANNEL_DATA']))
    msg.append(generate_uint32(self._remote_channel_number))
    msg.append(generate_string(to_send))
    self._send_packet(''.join(msg))

  def disconnect(self):
    # Send our exit status
    msg = []
    msg.append(generate_byte(SSH_MSG_NUMS['SSH_MSG_CHANNEL_REQUEST']))
    msg.append(generate_uint32(self._remote_channel_number))
    msg.append(generate_string('exit-status'))
    msg.append(generate_byte(0)) # False
    msg.append(generate_uint32(0)) # Exit status = 0
    self._send_packet(''.join(msg))

    # Then close the channel
    msg = []
    msg.append(generate_byte(SSH_MSG_NUMS['SSH_MSG_CHANNEL_CLOSE']))
    msg.append(generate_uint32(self._remote_channel_number))
    self._send_packet(''.join(msg))

    # Read back the remote side's exit status
    data = self._read_packet()
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
    msg = []
    msg.append(generate_byte(SSH_MSG_NUMS['SSH_MSG_DISCONNECT']))
    msg.append(generate_uint32(11)) # SSH_DISCONNECT_BY_APPLICATION
    msg.append(generate_string('Closed by client'))
    msg.append(generate_string(''))
    self._send_packet(''.join(msg))

    # Receive their "close channel ACK"
    data = self._read_packet()
    index, msg_type = parse_byte(data, 0)
    index, recipient_channel = parse_uint32(data, index)

    assert msg_type == SSH_MSG_NUMS['SSH_MSG_CHANNEL_CLOSE']
    assert recipient_channel == self._local_channel_number

    print colors.cyan('Disconnected!')

    return exit_status

  def _send_and_receive_id_strings(self):
    # Send our own header
    self._socket.sendall(self._client_id_string)

    # Receive the server's ID string (max size 255, as specified by the RFC)
    self._server_id_string = self._socket.recv(255)
    match = re.match(r'SSH-([^-]+)-([^ ]+)(?:( .*))?\r\n', self._server_id_string)
    assert match, 'Could not parse server ID string'

    # Check that we're speaking the right protocol
    proto_version, software_version, comments = match.groups()
    assert proto_version == '2.0', "Unknown SSH protocol version" % proto_version

    print colors.cyan("Great! I'm speaking to %s (%s)" % (software_version, comments))

  def _do_key_exchange(self):
    # Generate and send our side of the kex exchange handshake
    client_kex_init = generate_client_kex_init()
    self._send_packet(client_kex_init, encrypted=False)

    # Receive the server's side of the key exchange handshake
    server_kex_init = self._read_packet(encrypted=False)
    data_ptr, ssh_msg_type = parse_byte(server_kex_init, 0)
    assert ssh_msg_type == SSH_MSG_NUMS['SSH_MSG_KEXINIT']

    # Read the cookie from the server
    cookie = server_kex_init[data_ptr:data_ptr + COOKIE_LEN]
    data_ptr += COOKIE_LEN
    print colors.cyan('Cookie: %s' % repr(cookie))

    # Read the algorithm lists from the server
    data_ptr, kex_algorithms = parse_name_list(server_kex_init, data_ptr)
    data_ptr, server_host_key_algorithms = parse_name_list(server_kex_init, data_ptr)
    data_ptr, encryption_algorithms_client_to_server = parse_name_list(server_kex_init, data_ptr)
    data_ptr, encryption_algorithms_server_to_client = parse_name_list(server_kex_init, data_ptr)
    data_ptr, mac_algorithms_client_to_server = parse_name_list(server_kex_init, data_ptr)
    data_ptr, mac_algorithms_server_to_client = parse_name_list(server_kex_init, data_ptr)
    data_ptr, compression_algorithms_client_to_server = parse_name_list(server_kex_init, data_ptr)
    data_ptr, compression_algorithms_server_to_client = parse_name_list(server_kex_init, data_ptr)
    data_ptr, _ = parse_name_list(server_kex_init, data_ptr)
    data_ptr, _ = parse_name_list(server_kex_init, data_ptr)

    # Check that the server did not try to predict the key exchange protocol we'd be using
    data_ptr, first_kex_packet_follows = parse_byte(server_kex_init, data_ptr)
    assert first_kex_packet_follows == 0, 'Additional data in key exchange packet'

    # Check that the reserved bytes are also present in the message
    assert len(server_kex_init) == data_ptr + KEX_RESERVED_BYTES_LEN, 'Wrong amount of data left in packet'

    # Check that we'll be able to talk to this server correctly
    assert KEX_ALGORITHM in kex_algorithms
    assert SERVER_HOST_KEY_ALGORITHM in server_host_key_algorithms
    assert ENCRYPTION_ALGORITHM in encryption_algorithms_client_to_server
    assert ENCRYPTION_ALGORITHM in encryption_algorithms_server_to_client
    assert MAC_ALGORITHM in mac_algorithms_client_to_server
    assert MAC_ALGORITHM in mac_algorithms_server_to_client
    assert COMPRESSION_ALGORITHM in compression_algorithms_client_to_server
    assert COMPRESSION_ALGORITHM in compression_algorithms_server_to_client

    # Derive Diffie Hellman shared keys
    self._run_diffie_hellman_group14_sha1_key_exchange(server_kex_init, client_kex_init)

    # Swap to using those keys
    self._send_packet(generate_byte(SSH_MSG_NUMS['SSH_MSG_NEWKEYS']), encrypted=False)
    response = self._read_packet(encrypted=False)
    index, response_type = parse_byte(response, 0)
    assert response_type == SSH_MSG_NUMS['SSH_MSG_NEWKEYS'], 'Unknown SSH message type: %d' % response_type
    assert index == len(response), 'Additional data in response'

    print colors.cyan('Successfully exchanged keys!')

  def _do_user_auth(self):
    # Ask the server whether it supports doing SSH user auth
    msg = []
    msg.append(generate_byte(SSH_MSG_NUMS['SSH_MSG_SERVICE_REQUEST']))
    msg.append(generate_string(SSH_USERAUTH_STRING))
    self._send_packet(''.join(msg))

    # Check that it says yes
    data = self._read_packet()
    index, msg_type = parse_byte(data, 0)
    assert msg_type == SSH_MSG_NUMS['SSH_MSG_SERVICE_ACCEPT'], 'Unknown message type received: %d' % msg_type
    index, service_name = parse_string(data, index)
    assert service_name == SSH_USERAUTH_STRING

    print colors.cyan("Let's do ssh-userauth!")

    # Ask the server which authentication methods it supports
    msg = []
    msg.append(generate_byte(SSH_MSG_NUMS['SSH_MSG_USERAUTH_REQUEST']))
    msg.append(generate_string(self.username.encode('utf-8')))
    msg.append(generate_string('ssh-connection'))
    msg.append(generate_string('none'))
    self._send_packet(''.join(msg))

    # Check that publickey is one of them
    data = self._read_packet()
    index, msg_type = parse_byte(data, 0)
    index, supported_auth_methods = parse_name_list(data, index)
    index, partial_success_byte = parse_byte(data, index)
    partial_success = partial_success_byte != 0

    assert msg_type == SSH_MSG_NUMS['SSH_MSG_USERAUTH_FAILURE'], 'Unknown message type: %d' % msg_type
    assert 'publickey' in supported_auth_methods, 'Server does not support public key authentication'
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
    msg.append(generate_string(generate_string('ssh-rsa') + generate_mpint(rsa_key.e) + generate_mpint(rsa_key.n)))

    # Desperately try to figure out how signing works in this silly encapsulating protocol
    signed_data = generate_string(self._session_id) + ''.join(msg)
    signature = pkcs_key.sign(SHA.new(signed_data)) # OMG Pycrypto, did it have to be *your* SHA1 implementation?
    msg.append(generate_string(generate_string('ssh-rsa') + generate_string(signature)))

    # Send the public key auth message to the server
    self._send_packet(''.join(msg))

    data = self._read_packet()
    index, msg_type = parse_byte(data, 0)
    assert msg_type == SSH_MSG_NUMS['SSH_MSG_USERAUTH_SUCCESS'], 'Unknown message type: %d' % msg_type

    print colors.cyan('Successfully user authed!')

  def _create_ssh_connection(self):
    # Read the global request that SSH sends us - this is trying to let us know all host keys, but
    # it's OpenSSH-specific, and we don't need it
    data = self._read_packet()
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
    self._send_packet(''.join(msg))

    # Actually get started with opening a channel for SSH communication
    self._local_channel_number = 0
    window_size = 1048576
    maximum_packet_size = 16384

    # Request to open a session channel
    msg = []
    msg.append(generate_byte(SSH_MSG_NUMS['SSH_MSG_CHANNEL_OPEN']))
    msg.append(generate_string('session'))
    msg.append(generate_uint32(self._local_channel_number))
    msg.append(generate_uint32(window_size))
    msg.append(generate_uint32(maximum_packet_size))
    self._send_packet(''.join(msg))

    # Check that a channel was opened successfully
    data = self._read_packet()
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
    self._send_packet(''.join(msg))

    # OpenSSH then asks to increase their window size, that's fine, do it
    data = self._read_packet()
    index, msg_type = parse_byte(data, 0)
    index, recipient_channel = parse_uint32(data, index)
    index, bytes_to_add = parse_uint32(data, index)
    assert msg_type == SSH_MSG_NUMS['SSH_MSG_CHANNEL_WINDOW_ADJUST']
    initial_window_size += bytes_to_add

    # Check that they tell us they've opened a channel successfully
    data = self._read_packet()
    index, msg_type = parse_byte(data, 0)

    assert msg_type == SSH_MSG_NUMS['SSH_MSG_CHANNEL_SUCCESS']
    assert recipient_channel == self._local_channel_number

    print colors.cyan('Successfully opened shell!')

  def _run_diffie_hellman_group14_sha1_key_exchange(self, server_kex_init, client_kex_init):
    # q, g, and p from https://tools.ietf.org/html/rfc3526#section-3
    q = 2 ** 2048
    g = 2
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    x = random.SystemRandom().randint(2, q - 1)
    e = pow(g, x, p)

    # Send public key to server
    msg = []
    msg.append(generate_byte(SSH_MSG_NUMS['SSH_MSG_KEXDH_INIT']))
    msg.append(generate_mpint(e))
    self._send_packet(''.join(msg), encrypted=False)

    # Receive (K_S || f || s) from the server
    # i.e. host key blob, f, and the signature, from the server
    msg = self._read_packet(encrypted=False)
    index, ssh_msg_type = parse_byte(msg, 0)
    assert ssh_msg_type == SSH_MSG_NUMS['SSH_MSG_KEXDH_REPLY']

    index, host_key_blob = parse_string(msg, index)
    index, f = parse_mpint(msg, index)
    index, signature = parse_string(msg, index)

    # Calculate a verifying key from the host key blob
    verifying_key = self._get_verifying_key(host_key_blob)

    # Also calculate the shared key, exchange hash, and session ID (this is the same as the exchange
    # hash)
    shared_key = pow(f, x, p)
    hashed_data = \
      generate_string(self._client_id_string.strip('\r\n')) + \
      generate_string(self._server_id_string.strip('\r\n')) + \
      generate_string(client_kex_init) + \
      generate_string(server_kex_init) + \
      generate_string(host_key_blob) + \
      generate_mpint(e) + \
      generate_mpint(f) + \
      generate_mpint(shared_key)
    exchange_hash = hashlib.sha1(hashed_data).digest()
    self._session_id = exchange_hash

    # Pull out the signature blob from the message
    index, ecdsa_identifier = parse_string(signature, 0)
    assert ecdsa_identifier == SERVER_HOST_KEY_ALGORITHM, 'Unknown signature type: %s' % ecdsa_identifier
    index, signature_blob = parse_string(signature, index)

    index, r = parse_mpint(signature_blob, 0)
    index, s = parse_mpint(signature_blob, index)

    # Verify that the signature on the message is correct
    assert verifying_key.verify(
        get_32_byte_repr(r) + get_32_byte_repr(s),
        exchange_hash,
        hashfunc=hashlib.sha256,
        sigdecode=ecdsa.util.sigdecode_string
    )
    print colors.cyan('Signature validated correctly! OMG!')

    # Derive *all* the keys!
    key_derivation_options = {
        'shared_key': shared_key,
        'exchange_hash': exchange_hash,
        'session_id': self._session_id,
    }

    # Client to server keys
    initial_iv_client_to_server = derive_encryption_key(key_derivation_options, 'A', AES_BLOCK_LEN)
    ctr = Counter.new(AES_BLOCK_LEN * 8, initial_value=int(initial_iv_client_to_server.encode('hex'), AES_BLOCK_LEN))
    encryption_key_client_to_server = derive_encryption_key(key_derivation_options, 'C', AES_BLOCK_LEN)
    self._aes_client_to_server = AES.new(encryption_key_client_to_server, AES.MODE_CTR, counter=ctr)
    self._integrity_key_client_to_server = derive_encryption_key(key_derivation_options, 'E')

    # Server to client keys
    initial_iv_server_to_client = derive_encryption_key(key_derivation_options, 'B', AES_BLOCK_LEN)
    ctr = Counter.new(AES_BLOCK_LEN * 8, initial_value=int(initial_iv_server_to_client.encode('hex'), AES_BLOCK_LEN))
    encryption_key_server_to_client = derive_encryption_key(key_derivation_options, 'D', AES_BLOCK_LEN)
    self._aes_server_to_client = AES.new(encryption_key_server_to_client, AES.MODE_CTR, counter=ctr)
    self._integrity_key_server_to_client = derive_encryption_key(key_derivation_options, 'F')

  def _get_verifying_key(self, host_key_blob):
    # Parse the received data from the host_key_blob
    index, host_key_type = parse_string(host_key_blob, 0)
    index, curve_name = parse_string(host_key_blob, index)
    index, host_public_key = parse_string(host_key_blob, index)

    # Find the expected host key in ~/.ssh/known_hosts
    expected_host_key_type = None
    expected_host_public_key = None
    known_hosts_filename = os.path.expanduser('~/.ssh/known_hosts')
    for line in open(known_hosts_filename, 'r'):
      if len(line.strip()) > 0:
        current_hostname, current_key_type, current_key = line.split(' ')
        if current_hostname == self.hostname:
          expected_host_key_type = current_key_type
          expected_host_public_key = current_key.decode('base64')
          break

    # If we *did* find the host key (i.e. we've already connected to this server), check that
    # everything matches
    if expected_host_key_type is not None:
      assert host_key_type == expected_host_key_type, 'Unexpected host key type: %s' % host_key_type
      assert curve_name == 'nistp256', 'Unknown curve name: %s' % curve_name
      assert host_key_blob == expected_host_public_key, 'Unexpected host public key: %s' % repr(host_key_blob)

    # Otherwise, if we haven't seen the host key before, prompt the user to see if they're okay with
    # that
    else:
      assert host_key_type == 'ecdsa-sha2-nistp256', 'Unknown host key type: %s' % host_key_type
      key_fingerprint = hashlib.sha256(host_key_blob).digest().encode('base64').replace('\n', '').rstrip('=')

      print "The authenticity of host '%s' can't be established." % self.hostname
      print "ECDSA key fingerprint is SHA256:%s." % key_fingerprint
      answer = raw_input("Are you sure you want to continue connecting (yes/no)?\n").strip()
      while answer not in ['yes', 'no', '']:
        answer = raw_input("Please type 'yes' or 'no': ").strip()

      # Add key to ~/.ssh/known_hosts
      if answer == 'yes':
        with open(known_hosts_filename, 'a') as known_hosts_file:
          known_hosts_file.write('%s %s %s\n' % (self.hostname, host_key_type, host_key_blob.encode('base64').replace('\n', '')))

      else:
        assert False, 'Host key verification failed.'

    # FIXME: NFI why we need to skip a byte here - I can't find this format documented anywhere
    assert host_public_key[0] == '\x04'
    return ecdsa.VerifyingKey.from_string(host_public_key[1:], curve=ecdsa.NIST256p)

  def _read_packet(self, encrypted=True):
    # Read the first <block_len> bytes of the packet, decrypt it if necessary, and parse out the
    # remaining packet length
    initial_packet = self._socket.recv(AES_BLOCK_LEN)
    if encrypted:
      initial_packet = self._aes_server_to_client.decrypt(initial_packet)
    _, packet_len = parse_uint32(initial_packet, 0)

    # Read the remaining bytes of the packet, decrypting if necessary, and checking the MAC
    remaining_msg = self._socket.recv(packet_len - (AES_BLOCK_LEN - 4))
    if encrypted:
      remaining_msg = self._aes_server_to_client.decrypt(remaining_msg)

      # Read and verify the MAC
      received_mac = self._socket.recv(SHA1_LEN)
      calculated_mac = hmac.new(
          self._integrity_key_server_to_client,
          generate_uint32(self._packets_received_counter) + initial_packet + remaining_msg,
          hashlib.sha1
      ).digest()
      assert received_mac == calculated_mac, 'MACs did not match: %s != %s' % (repr(received_mac), repr(calculated_mac))
      print colors.cyan('MAC validated correctly!')

    # Pull the payload out of the message
    data = (initial_packet + remaining_msg)[4:]
    index, padding_len = parse_byte(data, 0)
    payload_len = packet_len - padding_len - index
    payload = data[index:payload_len + index]

    self._packets_received_counter += 1
    print colors.green('< Received: %s' % repr(payload))

    return payload

  def _send_packet(self, payload, encrypted=True):
    # This maths is horrific, but essentially we're calculating how much padding we need to add,
    # given that we must have at least 4 bytes, and that the total message length must be a multiple
    # of the AES block length
    padding_len = MIN_PADDING_LEN
    padding_len += AES_BLOCK_LEN - ((4 + 1 + len(payload) + padding_len) % AES_BLOCK_LEN)
    packet_len = 1 + len(payload) + padding_len

    msg_parts = []
    msg_parts.append(generate_uint32(packet_len))
    msg_parts.append(generate_byte(padding_len))
    msg_parts.append(payload)
    msg_parts.append(random_bytes(padding_len))

    msg = ''.join(msg_parts)
    # If the packet is encrypted, add the MAC and encrypt the message. The weird order of operations
    # here is because SSH is encrypt-and-mac (that is, the mac is on the plaintext, which is also
    # encrypted), rather than encrypt-then-mac or mac-then-encrypt
    if encrypted:
      mac = hmac.new(
          self._integrity_key_client_to_server,
          generate_uint32(self._packets_sent_counter) + msg,
          hashlib.sha1
      ).digest()

      msg = self._aes_client_to_server.encrypt(msg)
      msg += mac

    self._packets_sent_counter += 1
    print colors.magenta('> Sending: %s' % repr(''.join(msg)))
    self._socket.send(msg)

def derive_encryption_key(opts, id_char, key_length=20):
  assert key_length <= SHA1_LEN

  return hashlib.sha1(
      generate_mpint(opts['shared_key']) + \
      opts['exchange_hash'] + \
      id_char + \
      opts['session_id']
  ).digest()[:key_length]

def generate_client_kex_init():
  msg = []
  msg.append(generate_byte(SSH_MSG_NUMS['SSH_MSG_KEXINIT']))
  msg.append(random_bytes(COOKIE_LEN))

  msg.append(generate_name_list([KEX_ALGORITHM]))
  msg.append(generate_name_list([SERVER_HOST_KEY_ALGORITHM]))
  msg.append(generate_name_list([ENCRYPTION_ALGORITHM]))
  msg.append(generate_name_list([ENCRYPTION_ALGORITHM]))
  msg.append(generate_name_list([MAC_ALGORITHM]))
  msg.append(generate_name_list([MAC_ALGORITHM]))
  msg.append(generate_name_list([COMPRESSION_ALGORITHM]))
  msg.append(generate_name_list([COMPRESSION_ALGORITHM]))
  msg.append(generate_name_list([]))
  msg.append(generate_name_list([]))

  msg.append(generate_byte(0)) # Additional data being sent = False
  msg.append('\x00\x00\x00\x00') # Reserved bytes

  return ''.join(msg)

if __name__ == '__main__':
  sys.exit(main(sys.argv))
