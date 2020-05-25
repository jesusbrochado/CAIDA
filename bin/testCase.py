

from checkCase import CheckCase

print("===== acl_mismatch =========================================================")
res = CheckCase('../logs/acl_mismatch.txt')
print(res.extractInfo())

print("===== Auth_Method_Mismatch =========================================================")

res = CheckCase('../logs/Auth_Method_Mismatch.txt')
print(res.extractInfo())

print("===== CryptoMapIncomplete =========================================================")

res = CheckCase('../logs/CryptoMapIncomplete.txt')
print(res.extractInfo())

print("====== Encryption_ThenEncryptionAndGroup ========================================================")

res = CheckCase('../logs/Encryption_ThenEncryptionAndGroup.txt')
print(res.extractInfo())

print("======== EncryptionAndPRF_Resp ======================================================")

res = CheckCase('../logs/EncryptionAndPRF_Resp.txt')
print(res.extractInfo())

print("========= EncryptionP1 =====================================================")

res = CheckCase('../logs/EncryptionP1.txt')
print(res.extractInfo())

print("========== mismatch_DH_Group ====================================================")

res = CheckCase('../logs/mismatch_DH_Group.txt')
print(res.extractInfo())

print("========= Mismatch_encry_hash_prf =====================================================")

res = CheckCase('../logs/Mismatch_encry_hash_prf.txt')
print(res.extractInfo())

print("========= P1Mismatch_2 =====================================================")

res = CheckCase('../logs/P1Mismatch_2.txt')
print(res.extractInfo())

print("========= P1MismatchInit =====================================================")

res = CheckCase('../logs/P1MismatchInit.txt')
print(res.extractInfo())

print("========== PSK_Init ====================================================")

res = CheckCase('../logs/PSK_Init.txt')
print(res.extractInfo())

print("========== PSK_Mismatch_init ====================================================")

res = CheckCase('../logs/PSK_Mismatch_init.txt')
print(res.extractInfo())

print("========== PSK_Mismatch_resp ====================================================")

res = CheckCase('../logs/PSK_Mismatch_resp.txt')
print(res.extractInfo())

print("========== PSK_REsponder ====================================================")

res = CheckCase('../logs/PSK_REsponder.txt')
print(res.extractInfo())

print("========= TSet_Mismatch_initiator =====================================================")

res = CheckCase('../logs/TSet_Mismatch_initiator.txt')
print(res.extractInfo())

print("========= TSet_Mismatch_responder =====================================================")

res = CheckCase('../logs/TSet_Mismatch_responder.txt')
print(res.extractInfo())