#!/usr/bin/env python3
# encoding: utf-8
#Imports
from code import lambdas, functions
import re

## DECLARATIONS
userLog = lambdas.readDebugs('../pub/debugs/userlog.txt') # is constant for now!!!
filters = lambdas.csvToDict('logs_init.csv')

# Here we extract key data from the string get userLog that user enter to the system.
iniciator = True if re.search(r'Received PFKEY Acquire SA for SPI 0x0, error FALSE',userLog) else  False
peer = re.search('attempting to find tunnel group for IP:(.+?)\n', userLog).group(1)
proposalType = re.search('my_auth_method = (.+?)\n', userLog).group(1) #Proposal type: 1 PKI, 2 PSK
tunnelType = re.search('tunn grp type set to: (.+?)\n', userLog).group(1)

#Special case this must be a collection NEED REFIX IT
proposal_phase_1 = re.search('Proposal: (.+?), Protocol', userLog).group(1)
protocol_phase_1 = re.search('Protocol id: (.+?), SPI', userLog).group(1)
# PLEASE DONT FORGET THESE TOO:
#type: 1, reserved: 0x0, id: AES-CBC
#type: 2, reserved: 0x0, id: SHA256
#type: 3, reserved: 0x0, id: SHA256
#type: 4, reserved: 0x0, id: DH_GROUP_2048_MODP/Group 14
#(2): IKEv2 IKE_SA_INIT Exchange RESPONSEIKEv2-PROTO-3: (2): Next payload: SA, version: 2.0 (2): Exchange type: IKE_SA_INIT, flags: RESPONDER MSG-RESPONSE (2): Message id: 0, length: 574(2):

# I AM NOT CLEAR YET, may is the up forward
# type: 1, reserved: 0x0, id: AES-CBC
# type: 2, reserved: 0x0, id: SHA256
# type: 3, reserved: 0x0, id: SHA256
# type: 4, reserved: 0x0, id: DH_GROUP_2048_MODP/Group 14

phase_1 = True if re.search(r'(I) MsgID = 00000000 CurState: INIT_DONE Event: EV_CHK4_ROLE',userLog) else  False

# Phase 2 extractiong
noNATfound = True if re.search(r'No NAT found',userLog) else  False

# localKeyLength #Question what establish if is remote or local?
# remoteKeyLength #Question what establish if is remote or local?

localAuthentication = re.search("My authentication method is '(.+?)'", userLog).group(1)

# proposal_phase_2 // wait
# protocol_phase_2 // wait
 
proposal_number_phase_2 = re.search('Num of TSs: (.+?), reserved 0x0, reserved 0x0', userLog).group(1)
peerAuthenticationType = re.search('peer auth method set to: (.+?)\n', userLog).group(1) # 1 PKI, 2 PSK
peerAuthenticationComplete = True if re.search(r'Completed authentication for connection',userLog) else  False
idleTimeout = re.search('idle timeout set to: (.+?)\n', userLog).group(1)
sessionTimeout = re.search('session timeout set to: (.+?)\n', userLog).group(1)
nameGroupPolicy = re.search('group policy set to (.+?)\n', userLog).group(1)
DPDtimer = re.search('Initializing DPD, configured for (.+?) seconds', userLog).group(1)
cryptoMapSecuence = re.search('PROXY MATCH on crypto map CRY_MAP seq (.+?)\n', userLog).group(1)
I_SPI = re.search('SM Trace-> SA: I_SPI=(.+?) R_SPI=', userLog).group(1)
## Add ignore some value for regex
R_SPI = re.search('SM Trace-> SA: I_SPI=' + I_SPI + ' R_SPI=(.+?) \(I\) MsgID = 00000001 CurState: READY Event:', userLog).group(1)
tunelUp = True if re.search(r'CurState: READY Event: EV_I_OK',userLog) else  False


print("iniciator: ", iniciator)
print("peer: ", peer)
print("proposalType: ", proposalType)
print("tunnelType: ", tunnelType)
print("proposal_phase_1", proposal_phase_1)
print("protocol_phase_1", protocol_phase_1)
print("Phase 1 is enable: ", phase_1)
print("No NAT found: ", noNATfound)
print("localAuthentication: ", localAuthentication)
print("proposal_number_phase_2: ", proposal_number_phase_2)
print("authenticationPeerType: ", peerAuthenticationType)
print("peerAuthenticationComplete: ", peerAuthenticationComplete)
print("idleTimeout: ", idleTimeout)
print("sessionTimeout: ", sessionTimeout)
print("nameGroupPolicy: ", nameGroupPolicy)
print("DPDtimer: ", DPDtimer)
print("cryptoMapSecuence: ", cryptoMapSecuence)
print("I_SPI: ", I_SPI)
print("R_SPI: ", R_SPI)
print("tunelUp: ", tunelUp)




#dici = [['\n'+'Your initial configuration is :'+'\n']]
#functions.conf_ini(initiator,filters,dici)
#for row in dici:
#    lambdas.cprint(row)


