#!/usr/bin/env python3
# encoding: utf-8
#Imports
from code import lambdas, functions
import re

## DECLARATIONS
filePath = '../pub/debugs/userlog2.txt'
userLog = lambdas.readDebugs(filePath) # is constant for now!!!
filters = lambdas.csvToDict('logs_init.csv')


# Here we extract key data from the string get userLog that user enter to the system.
iniciator = True if re.search(r'Received PFKEY Acquire SA for SPI 0x0, error FALSE',userLog) else  False
peer = re.search('attempting to find tunnel group for IP:(.+?)\n', userLog).group(1)
proposalType = "PKI" if re.search('my_auth_method = (.+?)\n', userLog).group(1) == 1 else "PSK" #Proposal type: 1 PKI, 2 PSK
tunnelType = re.search('tunn grp type set to: (.+?)\n', userLog).group(1)

#Special case this must be a collection NEED REFIX IT
proposal_phase_1 = re.search('Proposal: (.+?), Protocol', userLog).group(1)
protocol_phase_1 = re.search('Protocol id: (.+?), SPI', userLog).group(1)
phase_1 = True if re.search(r'\(I\) MsgID = 00000000 CurState: INIT_DONE Event: EV_CHK4_ROLE',userLog) else  False

# Phase 2 extractiong
noNATfound = True if re.search(r'No NAT found',userLog) else  False

# localKeyLength #Question what establish if is remote or local?
# remoteKeyLength #Question what establish if is remote or local?

localAuthentication = re.search("My authentication method is '(.+?)'", userLog).group(1)

# proposal_phase_2 // wait
# protocol_phase_2 // wait

proposal_number_phase_2 = re.search('Num of TSs: (.+?), reserved 0x0, reserved 0x0', userLog).group(1)
peerAuthenticationType = "PKI" if re.search('peer auth method set to: (.+?)\n', userLog).group(1) == 1 else "PSK"# 1 PKI, 2 PSK
peerAuthenticationComplete = True if re.search(r'Completed authentication for connection',userLog) else  False
idleTimeout = re.search('idle timeout set to: (.+?)\n', userLog).group(1)
sessionTimeout = re.search('session timeout set to: (.+?)\n', userLog).group(1)
nameGroupPolicy = re.search('group policy set to (.+?)\n', userLog).group(1)
DPDtimer = re.search('Initializing DPD, configured for (.+?) seconds', userLog).group(1)
cryptoMapSecuence = re.search('PROXY MATCH on crypto map (.+?) seq (.+?)\n', userLog).group(1)
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
print("phase_1: ", phase_1)


def filterProposal(match_start, match_end):
    debug_file = open(filePath)

    debug_lines = debug_file.readlines()
    i=0
    res = ""
    try:
        for log in debug_lines:
            if re.search(r''+match_start, debug_lines[i]):
                while True:
                    if re.search(r''+match_end, debug_lines[i]):
                        return res
                    res += debug_lines[i]
                    i += 1
            i = i + 1
        return p1_prop_string
    except Exception:
        pass

#EXTRAER EN ARCHIVOS PEQUENIOS
p1_prop_string = filterProposal('Protocol id: IKE, SPI size: ', 'Next payload: VID')
p1_resp = filterProposal('Exchange type: IKE_SA_INIT, flags: RESPONDER MSG-RESPONSE', 'Next payload: VID')
p2_prop = filterProposal('Protocol id: ESP, SPI size:', '\):   Next payload: TSr')
sa_traffic_init_local = filterProposal('\):   Next payload: TSr', 'TSr(.+?):   Next payload: NOTIFY, reserve')
sa_traffic_init_remote = filterProposal('TSr(.+?):   Next payload: NOTIFY, reserve', 'NOTIFY\(INITIAL_CONTACT\)')
sa_traffic_agreed_local= filterProposal('TSi  Next payload: TSr', ' TSr  Next payload: NOTIFY, res')
sa_traffic_agreed_remote= filterProposal('TSr  Next payload: NOTIFY', 'CurState: I_WAIT_AUTH Event: EV_RECV_AUTH')


#LOAD PHASE 1 SENT
p1_proposal = re.findall('Proposal: (.+?)', p1_prop_string)
p1_proposal_encryption = re.findall('type: 1, reserved: 0x0, id: (.+?)\n', p1_prop_string)
p1_proposal_prf = re.findall('type: 2, reserved: 0x0, id: (.+?)\n', p1_prop_string)
p1_proposal_integrity = re.findall('type: 3, reserved: 0x0, id: (.+?)\n', p1_prop_string)
p1_proposal_group = re.findall('type: 4, reserved: 0x0, id: (.+?)\n', p1_prop_string)

#LOAD PHASE 1 RESP
p1_proposal_resp = re.findall('Proposal: (.+?)', p1_resp)
p1_proposal_encryption_resp = re.findall('type: 1, reserved: 0x0, id: (.+?)\n', p1_resp)
p1_proposal_prf_resp = re.findall('type: 2, reserved: 0x0, id: (.+?)\n', p1_resp)
p1_proposal_integrity_resp = re.findall('type: 3, reserved: 0x0, id: (.+?)\n', p1_resp)
p1_proposal_group_resp = re.findall('type: 4, reserved: 0x0, id: (.+?)\n', p1_resp)

#LOAD PHASE 2
p2_proposal = re.findall('Proposal: (.+?)', p2_prop)
p2_proposal_encryption = re.findall('type: 1, reserved: 0x0, id: (.+?)\n', p2_prop)
p2_proposal_hash = re.findall('type: 3, reserved: 0x0, id: (.+?)\n', p2_prop)
p2_proposal_esn = re.findall('type: 5, reserved: 0x0, id: (.+?)\n', p2_prop)

#INTERSTING TRAFFIC
local_sa_sent = re.findall('start addr: (.+?), end addr: (.+?)\n', sa_traffic_init_local)
remote_sa_sent = re.findall('start addr: (.+?), end addr: (.+?)\n', sa_traffic_init_remote)

agreed_sa_local = re.findall('start addr: (.+?), end addr: (.+?)\n', sa_traffic_agreed_local)
agreed_sa_remote = re.findall('start addr: (.+?), end addr: (.+?)\n', sa_traffic_agreed_remote)

print("=========================")
print("PROPOSALS SENT FROM INITIATOR")
print("=========================")

print(p1_proposal)
print(p1_proposal_encryption)
print(p1_proposal_prf)
print(p1_proposal_integrity)
print(p1_proposal_group)

print("=========================")
print("RESPONSE FROM RESPONDER")
print("=========================")

print(p1_proposal_resp)
print(p1_proposal_encryption_resp)
print(p1_proposal_prf_resp)
print(p1_proposal_integrity_resp)
print(p1_proposal_group_resp)


print("=========================")
print("Phase 2 Proposals")
print("=========================")

print(p2_proposal)
print(p2_proposal_encryption)
print(p2_proposal_hash)
print(p1_proposal_integrity_resp)
print(p2_proposal_esn)


print("=========================")
print("---   Interesting Traffic Local  Sent   ---")
print("=========================")


print(local_sa_sent)


print("=========================")
print("---   Interesting Traffic Remote  Sent   ---")
print("=========================")

print(remote_sa_sent)


print("=========================")
print("---   AGREED INTERSTING TRAFFIC   ---")
print("=========================")


print("Local SA :" , agreed_sa_local)
print("Remote SA :" , agreed_sa_remote)

#dici = [['\n'+'Your initial configuration is :'+'\n']]
#functions.conf_ini(initiator,filters,dici)
#for row in dici:
#    lambdas.cprint(row)


