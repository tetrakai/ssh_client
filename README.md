These files implement a very basic SSH client that can be used with Ubuntu 15.10 to understand the
SSH protocol.

Each message sent over the wire is logged to the console, and the implementation is split into
the transport and higher level protocols, as documented in the following SSH RFCs:

 - Overall architecture: https://tools.ietf.org/html/rfc4251
 - Transport layer: https://tools.ietf.org/html/rfc4253
 - User authentication protocol: https://tools.ietf.org/html/rfc4252
 - SSH connection protocol: https://tools.ietf.org/html/rfc4254
