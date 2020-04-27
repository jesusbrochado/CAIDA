#!/usr/bin/env python3
# encoding: utf-8
#Imports
from code import lambdas, functions
import re
filePath = '../pub/debugs/userlog2.txt'
userLog = lambdas.readDebugs(filePath) # is constant for now!!!
filters = lambdas.csvToDict('logs_init.csv')
iconfig = []

## DECLARATIONS

def main(userLog):
  
    # Here we extract key data from the string get userLog that user enter to the system.
    iniciator = True if re.search(r'EV_INIT_SA',userLog) else  False
    iconfig.append(iniciator)

    if ((functions.checkNotFound(re.search('attempting to find tunnel group for IP:(.+?)\n', userLog)) != "Not Found")):
        peer = functions.checkNotFound(re.search('Sending Packet \[To (.+?):', userLog))
        iconfig.append(peer)
    else:
        peer = functions.checkNotFound(re.search('attempting to find tunnel group for IP:(.+?)\n', userLog))
        iconfig.append(peer)

    if((functions.checkNotFound(re.search('my_auth_method = (.+?)\n', userLog) != "Not Found"))):
        proposalType = "PSK" if re.search('my_auth_method = (.+?)\n', userLog).group(1) == 2 else "PKI"
        iconfig.append(proposalType)

    else:
        proposalType = functions.checkNotFound(re.search('My authentication method is (.+?)\n', userLog))
        iconfig.append(proposalType)

    #tunnelType = re.search('tunn grp type set to: (.+?)\n', userLog).group(1) #"site to site by default, si encuentre entonces el string que encuentre"
    if (re.search('tunn grp type set to: (.+?)\n', userLog) is not None):
        tunnelType = re.search('tunn grp type set to: (.+?)\n', userLog)
        #iconfig.append(tunnelType)
    else:
        tunnelType = "site to site"
        iconfig.append(tunnelType)


    #Special case this must be a collection NEED REFIX IT
    proposal_phase_1 = functions.checkNotFound(re.search('Proposal: (.+?), Protocol', userLog))
    protocol_phase_1 = functions.checkNotFound(re.search('Protocol id: (.+?), SPI', userLog))
    phase_1 = True if re.search(r'\(I\) MsgID = 00000000 CurState: INIT_DONE Event: EV_CHK4_ROLE',userLog) else  False
    iconfig.append(phase_1)
    
    # NAT Detection
    noNATfound = True if re.search(r'No NAT found',userLog) else  False
    iconfig.append(noNATfound)
    us_NAT_T = True if re.search(r'NAT INSIDE found',userLog) else  False
    iconfig.append(us_NAT_T)
    remote_NAT_T = True if re.search(r'NAT OUTSIDE found',userLog) else  False
    iconfig.append(remote_NAT_T)




    # localKeyLength #Question what establish if is remote or local?
    # remoteKeyLength #Question what establish if is remote or local?

    localAuthentication = functions.checkNotFound(re.search("My authentication method is '(.+?)'", userLog))
    iconfig.append(localAuthentication)
    # proposal_phase_2 // wait
    # protocol_phase_2 // wait

    proposal_number_phase_2 = functions.checkNotFound(re.search('Num of TSs: (.+?), reserved 0x0, reserved 0x0', userLog))
    iconfig.append(proposal_number_phase_2)
    #PENDING!
    ## 1 PKI, 2 PSK  O si no hace match entonces "Peer's authentication method is" toca poner bien la comilla
    #

    if(re.search('peer auth method set to: (.+?)\n', userLog) is not None):
        peerAuthenticationType = "PSK" if re.search('peer auth method set to: (.+?)\n', userLog).group(1) == 2 else "PKI"
        iconfig.append(peerAuthenticationType)
    else:
        peerAuthenticationType = functions.checkNotFound(re.search("Peer's authentication method is '(.+?)'\n", userLog))
        iconfig.append(peerAuthenticationType)

    peerAuthenticationComplete = True if re.search(r'Completed authentication for connection',userLog) else  False
    iconfig.append(peerAuthenticationComplete)
    idleTimeout = functions.checkNotFound(re.search('idle timeout set to: (.+?)\n', userLog))
    iconfig.append(idleTimeout)
    sessionTimeout = functions.checkNotFound(re.search('session timeout set to: (.+?)\n', userLog))
    iconfig.append(sessionTimeout)
    nameGroupPolicy = functions.checkNotFound(re.search('group policy set to (.+?)\n', userLog))
    iconfig.append(nameGroupPolicy)
    DPDtimer = functions.checkNotFound(re.search('Initializing DPD, configured for (.+?) seconds', userLog))
    iconfig.append(DPDtimer)
    #PENDING!
    #cryptoMapSecuence = re.search('PROXY MATCH on crypto map (.+?) seq (.+?)\n', userLog).group(1)
    I_SPI = functions.checkNotFound(re.search('SM Trace-> SA: I_SPI=(.+?) R_SPI=', userLog))
    iconfig.append(I_SPI)
    ## Add ignore some value for regex
    R_SPI = functions.checkNotFound(re.search('SM Trace-> SA: I_SPI=' + I_SPI + ' R_SPI=(.+?) \(I\) MsgID = 00000001 CurState: READY Event:', userLog))
    iconfig.append(R_SPI)
    tunelUp = True if re.search(r'CurState: READY Event: EV_I_OK',userLog) else  False
    iconfig.append(tunelUp)


    print("iniciator: ", iniciator)
    print("peer: ", peer)
    print("proposalType: ", proposalType)
    print("tunnelType: ", tunnelType)
    print("proposal_phase_1", proposal_phase_1)
    print("protocol_phase_1", protocol_phase_1)
    print("Phase 1 is enable: ", phase_1)
    print("No NAT: ", noNATfound)
    print("NAT T Local: ", us_NAT_T)
    print("NAT T Remote: ", remote_NAT_T)
    print("localAuthentication: ", localAuthentication)
    print("proposal_number_phase_2: ", proposal_number_phase_2)
    print("authenticationPeerType: ", peerAuthenticationType)
    print("peerAuthenticationComplete: ", peerAuthenticationComplete)
    print("idleTimeout: ", idleTimeout)
    print("sessionTimeout: ", sessionTimeout)
    print("nameGroupPolicy: ", nameGroupPolicy)
    print("DPDtimer: ", DPDtimer)
    #print("cryptoMapSecuence: ", cryptoMapSecuence)
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

    #PENDINTE! SI LO DE ABAJO VACIO, ENTONCES USAR LA ULTIMA POSICION DE LAS LISTAS DE sa_traffic_init_local Y sa_traffic_init_remote

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
    if (p2_prop is not None): # flag p2_prop a veces llega None????
        p2_proposal = functions.checkNotFound(re.findall('Proposal: (.+?)', p2_prop))
        p2_proposal_encryption =functions.checkNotFound( re.findall('type: 1, reserved: 0x0, id: (.+?)\n', p2_prop))
        p2_proposal_hash = functions.checkNotFound(re.findall('type: 3, reserved: 0x0, id: (.+?)\n', p2_prop))
        p2_proposal_esn = functions.checkNotFound(re.findall('type: 5, reserved: 0x0, id: (.+?)\n', p2_prop))
    else:
        p2_proposal = "Not Found"
        p2_proposal_encryption = "Not Found"
        p2_proposal_hash = "Not Found"
        p2_proposal_esn = "Not Found"

    #INTERSTING TRAFFIC

    local_sa_sent = re.findall('start addr: (.+?), end addr: (.+?)\n', sa_traffic_init_local)

    if(sa_traffic_init_remote is not None): # flag este valor a vece llega como None????
        remote_sa_sent = re.findall('start addr: (.+?), end addr: (.+?)\n', sa_traffic_init_remote)
    else:
        remote_sa_sent = "Not Found"


    # Si sa_traffic_agreed_local y/o sa_traffic_agreed_remote estan vacios,entonces utilizar
    # la ultima posicion de las listas sa_traffic_init_local & sa_traffic_init_remote

    # tart addr: 172.16.0.20, end addr: 172.16.0.20

    agreed_sa_local = re.findall('start addr: (.+?), end addr: (.+?)\n', sa_traffic_agreed_local)
    if (len(agreed_sa_local) == 0):
        agreed_sa_local = [local_sa_sent[-1]]

    if (sa_traffic_agreed_remote is not None):
        agreed_sa_remote = re.findall('start addr: (.+?), end addr: (.+?)\n', sa_traffic_agreed_remote)
    else:
        agreed_sa_remote = "Not Found"

    if(len(agreed_sa_remote) == 0):
        agreed_sa_remote = [remote_sa_sent[-1]]

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

main(userLog)