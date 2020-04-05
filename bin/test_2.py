from infoExtractor import *

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
print("cryptoMapName: ", cryptoMapName)
print("cryptoMapSecuence: ", cryptoMapSecuence)
print("I_SPI: ", I_SPI)
print("R_SPI: ", R_SPI)
print("tunelUp: ", tunelUp)
print("phase_1: ", phase_1)

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
