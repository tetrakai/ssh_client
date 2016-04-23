import sys
import colors
from ssh_connection import SSHConnection

def main(argv):
  # Parse the username, hostname, and keyfile from the command line arguments
  username, hostname = argv[1].split('@')
  keyfile = argv[2]

  # Construct an SSH connection
  ssh = SSHConnection(hostname, username, keyfile)
  ssh.connect()

  # Run an interactive prompt, until the user enters an empty line or closes the input stream
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

  # Cleanly close the SSH connection
  exit_status = ssh.disconnect()
  return exit_status

if __name__ == '__main__':
  sys.exit(main(sys.argv))
