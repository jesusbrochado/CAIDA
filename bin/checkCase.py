import re
import lambdas, functions

class CheckCase():
    filePath = ""
    def __init__(self, filePath):
        self.filePath = filePath
    
    # function of the case
    def extractInfo(self):
        filePath = self.filePath
        userLog = lambdas.readDebugs(filePath)
        l10001 = functions.checkNotFoundCase(re.search('Received PFKEY Acquire SA for SPI 0x0, error FALSE', userLog))
        l11001 = functions.checkNotFoundCase(re.search('INVALID PSH HANDLE', userLog))
        l11002 = functions.checkNotFoundCase(re.search('attempting to find tunnel group for IP: (.+?)\n', userLog))
        l11003 = functions.checkNotFoundCase(re.search('mapped to tunnel group (.+?) using peer IP', userLog))
        l11008 = functions.checkNotFoundCase(re.search('Failed to set P1 auth to build policy', userLog))
        l11904 = functions.checkNotFoundCase(re.search("Can't find tunnel group for peer (.+?)\n", userLog))
        l11907 = functions.checkNotFoundCase(re.search('unable to set self auth method. Probable misconfiguration', userLog))
        l11917 = functions.checkNotFoundCase(re.search('Could not build ikev2 policy', userLog))
        l11918 = functions.checkNotFoundCase(re.search('asa connect start L2L failed', userLog))
        l11919 = functions.checkNotFoundCase(re.search('Parse Notify Payload: NO_PROPOSAL_CHOSEN(4):  NOTIFY(NO_PROPOSAL_CHOSEN)(4):   Next payload: NONE, reserved: 0x0, length: 8', userLog))
        l11920 = functions.checkNotFoundCase(re.search('Received no proposal chosen notify', userLog))
        l11921 = functions.checkNotFoundCase(re.search('Initial exchange failed', userLog))
        l11922 = functions.checkNotFoundCase(re.search('Negotiating SA request deleted', userLog))
        l11923 = functions.checkNotFoundCase(re.search('Abort exchange', userLog))
        l11925 = functions.checkNotFoundCase(re.search('NO_PROPOSAL_CHOSEN NOTIFY(NO_PROPOSAL_CHOSEN)', userLog))
        l13065 = functions.checkNotFoundCase(re.search('I_SPI=DCA635040E30A6A3 R_SPI=0000000000000000 (I) MsgID = 00000000 CurState: I_WAIT_INIT Event: EV_NO_EVENT', userLog))
        l13066 = functions.checkNotFoundCase(re.search('Retransmitting packet', userLog))
        l13128 = functions.checkNotFoundCase(re.search('Received Policies', userLog))
        l13129 = functions.checkNotFoundCase(re.search('Failed to find a matching policy', userLog))
        l13130 = functions.checkNotFoundCase(re.search('Expected Policies', userLog))
        l13967 = functions.checkNotFoundCase(re.search('Parse Notify Payload: AUTHENTICATION_FAILED NOTIFY(AUTHENTICATION_FAILED)', userLog))
        l13968 = functions.checkNotFoundCase(re.search('Failed to authenticate the IKE SA', userLog))
        l13969 = functions.checkNotFoundCase(re.search('Verify auth failed', userLog))
        l13970 = functions.checkNotFoundCase(re.search('Sending authentication failure notify', userLog))
        l13971 = functions.checkNotFoundCase(re.search('Auth exchange failed', userLog))
        l13972 = functions.checkNotFoundCase(re.search('Failed to receive the AUTH msg before the timer expired', userLog))

        logs = {
            "10001": l10001,
            "11001": l11001,
            "11002": l11002,
            "11003": l11003,
            "11008": l11008,
            "11904": l11904,
            "11907": l11907,
            "11917": l11917,
            "11918": l11918,
            "11919": l11919,
            "11920": l11920,
            "11921": l11921,
            "11922": l11922,
            "11923": l11923,
            "11925": l11925,
            "13065": l13065,
            "13066": l13066,
            "13128": l13128,
            "13129": l13129,
            "13130": l13130,
            "l13967":l13967,
            "l13968":l13968,
            "l13969":l13969,
            "l13970":l13970,
            "l13971":l13971,
            "l13972":l13972,
        }

        message = ""

        if functions.checkNotFound(re.search('attempting to find tunnel group for IP:(.+?)\n', userLog)) != "not found":
            peer = functions.checkNotFound(re.search('attempting to find tunnel group for IP:(.+?)\n', userLog))
        else:
            peer = functions.checkNotFound(re.search('attempting to find tunnel group for IP:(.+?)\n', userLog))

        if logs["11919"] and logs["11920"] and logs["11921"] and logs["11922"] and logs["11923"] or logs["11925"]:
            message = "Remote end sent no proposal chosen, verify phase 1 policies match"
        elif logs["11003"] and logs["11008"] and logs["11917"] and logs["11918"]:
            message = "tunnel-group for peer %s missing keys" % peer
        elif logs["13128"] and logs["13129"] and logs["13130"]:
            espCompare1 = re.search('Received Policies:\nESP: Proposal 1:  (.+?)\n', userLog)
            espCompare2 = re.search('Expected Policies:\nESP: Proposal 0:  (.+?)\n', userLog)
            compare1 = re.search('Received Policies:\nProposal 1:  (.+?)\n', userLog)
            compare2 = re.search('Expected Policies:\nProposal 1:  (.+?)\n', userLog)

            if compare1 is not None and compare2 is not None:
                compare1 = compare1.group(0)
                compare2 = compare2.group(0)

                compare1 = re.search('Proposal 1:  (.+?)\n', compare1).group(1)
                compare1 = compare1.split(" ")
                compare2 = re.search('Proposal 1:  (.+?)\n', compare2).group(1)
                compare2 = compare2.split(" ")

                if compare1[0] != compare2[0]:
                    message = message + "ENCRYPTION" + "; "

                if compare1[1] != compare2[1]:
                    message = message + "PRF" + "; "

                if compare1[2] != compare2[2]:
                    message = message + "HASH" + "; "

                if  "%s %s" % (compare1[3], compare1[4]) != "%s %s" % (compare2[3], compare2[4]):
                    message = message + "DH Group" + "; "

            elif(espCompare1 is not None and espCompare2 is not None):
                compare1 = espCompare1.group(0)
                compare2 = espCompare2.group(0)

                compare1 = re.search('ESP: Proposal 1:  (.+?)\n', compare1).group(1)
                compare1 = compare1.split(" ")
                compare2 = re.search('ESP: Proposal 0:  (.+?)\n', compare2).group(1)
                compare2 = compare2.split(" ")

                if compare1[0] != compare2[0]:
                    message = "Transform set mismatch on phase 2, verify that ENCRYPTION match"
                elif compare1[1] != compare2[1]:
                    message = "Transform set mismatch on phase 2, verify that HASH  match"
                elif compare1[0] != compare2[0] and compare1[1] != compare2[1]:
                    message = "Transform set mismatch on phase 2, verify that ENCRYPTION and HASH match"
            else:
                message = "Phase 2 mismatch, verify that on the crypto map configuration the proper peer IP, ACLs and transform sets are configured"

        elif logs["11003"] and logs["11917"] and logs["11918"] :
             message = "tunnel-group for peer %s missing keys" % peer
        elif logs["13065"] and logs["13966"] :
            message = "Remote end not replying to UDP 500 init message, possible device in betwen blocking comunication or remote end configure for the wrong peer"
        elif logs["11904"] and logs["11907"]:
            message = "Tunnel-group not configured, verify there is a tunnel-group configured for IP %s" % peer
        elif logs["10001"]:
            message = "Is initiator"

        return message


# ch = CheckCase('../pub/debugs/resp_error_no_peer_crymap_Nat-T.txt')
# print(ch.extractInfo())