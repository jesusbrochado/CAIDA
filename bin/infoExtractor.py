#!/usr/bin/env python3
# encoding: utf-8
#Imports
from code import lambdas, functions
import re

## DECLARATIONS
filePath = '../pub/debugs/userlog2.txt'
userLog = lambdas.readDebugs(filePath) # is constant for now!!!
filters = lambdas.csvToDict('logs_init.csv')
TXTNoFound = "Not found"

# Here we extract key data from the string get userLog that user enter to the system.
iniciator = True if re.search(r'EV_INIT_SA',userLog) else  False

if ((functions.checkNotFound(re.search('attempting to find tunnel group for IP:(.+?)\n', userLog)) != TXTNoFound)):
    peer = functions.checkNotFound(re.search('Sending Packet \[To (.+?):', userLog))
else:
    peer = functions.checkNotFound(re.search('attempting to find tunnel group for IP:(.+?)\n', userLog))

if((functions.checkNotFound(re.search('my_auth_method = (.+?)\n', userLog) != TXTNoFound))):
    proposalType = "PSK" if re.search('my_auth_method = (.+?)\n', userLog).group(1) == 2 else "PKI"
else:
    proposalType = functions.checkNotFound(re.search('My authentication method is (.+?)\n', userLog))


#tunnelType = re.search('tunn grp type set to: (.+?)\n', userLog).group(1) #"site to site by default, si encuentre entonces el string que encuentre"
if (re.search('tunn grp type set to: (.+?)\n', userLog) is not None):
    tunnelType = re.search('tunn grp type set to: (.+?)\n', userLog).group(1)
else:
    tunnelType = "site to site"

#Special case this must be a collection NEED REFIX IT
proposal_phase_1 = functions.checkNotFound(re.search('Proposal: (.+?), Protocol', userLog))
protocol_phase_1 = functions.checkNotFound(re.search('Protocol id: (.+?), SPI', userLog))
phase_1 = True if re.search(r'\(I\) MsgID = 00000000 CurState: INIT_DONE Event: EV_CHK4_ROLE',userLog) else  False

# NAT Detection
noNATfound = "No NAT found" if re.search(r'No NAT found',userLog) else  False
us_NAT_T = True if re.search(r'NAT INSIDE found',userLog) else  False
remote_NAT_T = True if re.search(r'NAT OUTSIDE found',userLog) else  False



# localKeyLength #Question what establish if is remote or local?
# remoteKeyLength #Question what establish if is remote or local?

localAuthentication = functions.checkNotFound(re.search("My authentication method is '(.+?)'", userLog))

# proposal_phase_2 // wait
# protocol_phase_2 // wait

proposal_number_phase_2 = functions.checkNotFound(re.search('Num of TSs: (.+?), reserved 0x0, reserved 0x0', userLog))

#PENDING!
## 1 PKI, 2 PSK  O si no hace match entonces "Peer's authentication method is" toca poner bien la comilla
#

if(re.search('peer auth method set to: (.+?)\n', userLog) is not None):
    peerAuthenticationType = "PSK" if re.search('peer auth method set to: (.+?)\n', userLog).group(1) == 2 else "PKI"
else:
    peerAuthenticationType = functions.checkNotFound(re.search("Peer's authentication method is '(.+?)'\n", userLog))


peerAuthenticationComplete = True if re.search(r'Completed authentication for connection',userLog) else  False
idleTimeout = functions.checkNotFound(re.search('idle timeout set to: (.+?)\n', userLog))
sessionTimeout = functions.checkNotFound(re.search('session timeout set to: (.+?)\n', userLog))
nameGroupPolicy = functions.checkNotFound(re.search('group policy set to (.+?)\n', userLog))
DPDtimer = functions.checkNotFound(re.search('Initializing DPD, configured for (.+?) seconds', userLog))

cryptoMapName = functions.checkNotFound(re.search('PROXY MATCH on crypto map (.+?) s', userLog))
cryptoMapSecuence = functions.checkNotFound(re.search('PROXY MATCH on crypto map '+ cryptoMapName + ' seq (.+?)\n', userLog))
I_SPI = functions.checkNotFound(re.search('SM Trace-> SA: I_SPI=(.+?) R_SPI=', userLog))
## Add ignore some value for regex
R_SPI = functions.checkNotFound(re.search('SM Trace-> SA: I_SPI=' + I_SPI + ' R_SPI=(.+?) \(I\) MsgID = 00000001 CurState: READY Event:', userLog))
tunelUp = True if re.search(r'CurState: READY Event: EV_I_OK',userLog) else  False

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
        return TXTNoFound

#EXTRAER EN ARCHIVOS PEQUENIOS
p1_prop_string = filterProposal('Protocol id: IKE, SPI size: ', 'Next payload: VID')
p1_resp = filterProposal('Exchange type: IKE_SA_INIT, flags: RESPONDER MSG-RESPONSE', 'Next payload: VID')
p2_prop = filterProposal('Protocol id: ESP, SPI size:', '\):   Next payload: TSr')
sa_traffic_init_local = filterProposal('\):   Next payload: TSr', 'TSr(.+?):   Next payload: NOTIFY, reserve')
sa_traffic_init_remote = filterProposal('TSr(.+?):   Next payload: NOTIFY, reserve', 'NOTIFY\(INITIAL_CONTACT\)')

#PENDINTE! SI LO DE ABAJO VACIO, ENTONCES USAR LA ULTIMA POSICION DE LAS LISTAS DE sa_traffic_init_local Y sa_traffic_init_remote

sa_traffic_agreed_local= filterProposal('TSi  Next payload: TSr', ' TSr  Next payload: NOTIFY, res')
sa_traffic_agreed_remote= filterProposal('TSr  Next payload: NOTIFY', 'CurState: I_WAIT_AUTH Event: EV_RECV_AUTH')

#LOAD PHASE 1 SENT
p1_proposal = functions.checkNotFoundArray(re.findall('Proposal: (.+?)', p1_prop_string))
p1_proposal_encryption = functions.checkNotFoundArray(re.findall('type: 1, reserved: 0x0, id: (.+?)\n', p1_prop_string))
p1_proposal_prf = functions.checkNotFoundArray(re.findall('type: 2, reserved: 0x0, id: (.+?)\n', p1_prop_string))
p1_proposal_integrity = functions.checkNotFoundArray(re.findall('type: 3, reserved: 0x0, id: (.+?)\n', p1_prop_string))
p1_proposal_group = functions.checkNotFoundArray(re.findall('type: 4, reserved: 0x0, id: (.+?)\n', p1_prop_string))

#LOAD PHASE 1 RESP
p1_proposal_resp = functions.checkNotFoundArray(re.findall('Proposal: (.+?)', p1_resp))
p1_proposal_encryption_resp = functions.checkNotFoundArray(re.findall('type: 1, reserved: 0x0, id: (.+?)\n', p1_resp))
p1_proposal_prf_resp = functions.checkNotFoundArray( re.findall('type: 2, reserved: 0x0, id: (.+?)\n', p1_resp))
p1_proposal_integrity_resp = functions.checkNotFoundArray(re.findall('type: 3, reserved: 0x0, id: (.+?)\n', p1_resp))
p1_proposal_group_resp = functions.checkNotFoundArray(re.findall('type: 4, reserved: 0x0, id: (.+?)\n', p1_resp))

#LOAD PHASE 2
if (p2_prop is not None and p2_prop != TXTNoFound):
    p2_proposal = functions.checkNotFoundArray(re.findall('Proposal: (.+?)', p2_prop))
    p2_proposal_encryption =functions.checkNotFoundArray(re.findall('type: 1, reserved: 0x0, id: (.+?)\n', p2_prop))
    p2_proposal_hash = functions.checkNotFoundArray(re.findall('type: 3, reserved: 0x0, id: (.+?)\n', p2_prop))
    p2_proposal_esn = functions.checkNotFoundArray(re.findall('type: 5, reserved: 0x0, id: (.+?)\n', p2_prop))
else:
    p2_proposal = TXTNoFound
    p2_proposal_encryption = TXTNoFound
    p2_proposal_hash = TXTNoFound
    p2_proposal_esn = TXTNoFound

#INTERSTING TRAFFIC
local_sa_sent = functions.checkNotFoundArray(re.findall('start addr: (.+?), end addr: (.+?)\n', sa_traffic_init_local))

if(sa_traffic_init_remote is not None and sa_traffic_init_remote != TXTNoFound):
    remote_sa_sent = re.findall('start addr: (.+?), end addr: (.+?)\n', sa_traffic_init_remote)
else:
    remote_sa_sent = TXTNoFound


# Si sa_traffic_agreed_local y/o sa_traffic_agreed_remote estan vacios,entonces utilizar
# la ultima posicion de las listas sa_traffic_init_local & sa_traffic_init_remote

# tart addr: 172.16.0.20, end addr: 172.16.0.20

agreed_sa_local = re.findall('start addr: (.+?), end addr: (.+?)\n', sa_traffic_agreed_local)
if (len(agreed_sa_local) == 0):
    agreed_sa_local = [local_sa_sent[-1]] if len(local_sa_sent) > 0 else TXTNoFound

if (sa_traffic_agreed_remote is not None):
    agreed_sa_remote = re.findall('start addr: (.+?), end addr: (.+?)\n', sa_traffic_agreed_remote)
else:
    agreed_sa_remote = TXTNoFound

if(len(agreed_sa_remote) == 0):
    agreed_sa_remote = [remote_sa_sent[-1]] if len(remote_sa_sent) > 0 else TXTNoFound

fase1 = {
    "Are we initiators": iniciator,
    "Peer": peer,
    # Revisar por que extraimos esto, parece que se corrompio
    # "Phase 1 proposals": proposal_phase_1,
    "Authentication Method": proposalType,
    "Tunnel Type": tunnelType,
    "Protocol Used": protocol_phase_1,
    "Phase 1 completed": phase_1,
    "Only UDP 500 (No NAT T)": noNATfound,
    "We are behind NAT": us_NAT_T,
    "Remote end behind NAT": remote_NAT_T,
    "Local Authnetication": localAuthentication,
    "peerAuthenticationType": peerAuthenticationType,
    "peerAuthenticationComplete": peerAuthenticationComplete,

    ## PROPOSALS SENT FROM INITIATOR
    ## Estos son todos los que enviamos, por ahora no se van a mostrar en GUI debeido a que son vectores
    #"p1_proposal": p1_proposal,
    #"p1_proposal_encryption": p1_proposal_encryption,
    #"p1_proposal_prf": p1_proposal_prf,
    #"p1_proposal_integrity": p1_proposal_integrity,
    #"p1_proposal_group": p1_proposal_group,
    ## RESPONSE FROM RESPONDER
    #"p1_proposal_resp": p1_proposal_resp,
    "Agreed encryption": p1_proposal_encryption_resp,
    "Agreed PRF group": p1_proposal_prf_resp,
    "Agreed hashing": p1_proposal_integrity_resp,
    "Agreed DH Group": p1_proposal_group_resp,

}


fase2 = {
    "Amount of Phase 2 proposals sent": proposal_number_phase_2,
    ## Phase 2 Proposals
    "p2_proposal": p2_proposal,
    "p2_proposal_encryption": p2_proposal_encryption,
    "p2_proposal_hash": p2_proposal_hash,
    "p2_proposal_esn": p2_proposal_esn,
    ## Interesting Traffic Local  Sent
    "Local encryption domain": local_sa_sent,
    ## Interesting Traffic Remote  Sent
    "Remote encryption domain": remote_sa_sent,
    ## AGREED INTERSTING TRAFFIC
    "Agreed SA Local": agreed_sa_local,
    "Agreed SA Remote": agreed_sa_remote
}

misc = {
    "Idle Timeout": idleTimeout,
    "Session Timeout": sessionTimeout,
    "Matched Group-Policy": nameGroupPolicy,
    "DPD Timer": DPDtimer,
    "Initiator SPI": I_SPI,
    "Responder SPI": R_SPI,
    "Tunnel established!": tunelUp,
}

def infoExtractor(result):
    return result