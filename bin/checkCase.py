import re
import lambdas, functions

class CheckCase():
    filePath = "../pub/debugs/userlog2.txt"
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
        l13065 = functions.checkNotFoundCase(re.search('R_SPI=0000000000000000 \(I\) MsgID = 00000000 CurState: I_WAIT_INIT Event: EV_NO_EVENT', userLog))
        l13128 = functions.checkNotFoundCase(re.search('Received Policies', userLog))
        l13129 = functions.checkNotFoundCase(re.search('Failed to find a matching policy', userLog))
        l13130 = functions.checkNotFoundCase(re.search('Expected Policies', userLog))
        l13931 = functions.checkNotFoundCase(re.search('Failed SA init exchange', userLog))
        l13932 = functions.checkNotFoundCase(re.search('Initial exchange failed', userLog))
        l13966 = functions.checkNotFoundCase(re.search('Retransmitting packet', userLog))
        l13967 = functions.checkNotFoundCase(re.search('Parse Notify Payload: AUTHENTICATION_FAILED NOTIFY(AUTHENTICATION_FAILED)', userLog))
        l13968 = functions.checkNotFoundCase(re.search('Failed to authenticate the IKE SA', userLog))
        l13969 = functions.checkNotFoundCase(re.search('Verify auth failed', userLog))
        l13970 = functions.checkNotFoundCase(re.search('Sending authentication failure notify', userLog))
        l13971 = functions.checkNotFoundCase(re.search('Auth exchange failed', userLog))
        l13972 = functions.checkNotFoundCase(re.search('Failed to receive the AUTH msg before the timer expired', userLog))
        l13973 = functions.checkNotFoundCase(re.search('Peer authentication method configured is mismatching with the method proposed by peer', userLog))
        l13974 = functions.checkNotFoundCase(re.search('Computed authentication value for peer differs from what peer sent', userLog))
        l13975 = functions.checkNotFoundCase(re.search('\(AUTHENTICATION_FAILED\)', userLog))
        l490 = functions.checkNotFoundCase(re.search('Parse Notify Payload: NO_PROPOSAL_CHOSEN NOTIFY\(NO_PROPOSAL_CHOSEN\)', userLog))
        l491 = functions.checkNotFoundCase(re.search('type: NO_PROPOSAL_CHOSEN', userLog))
        l492 = functions.checkNotFoundCase(re.search('Crypto map <VARIABLE1> seq <SEQ> is incomplete due to <VARIABLE2>', userLog))
        

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
            "13128": l13128,
            "13129": l13129,
            "13130": l13130,
            "13931": l13931,
            "13932": l13932,
            "13966": l13966,
            "13967": l13967,
            "13968": l13968,
            "13969": l13969,
            "13970": l13970,
            "13971": l13971,
            "13972": l13972,
            "13973":l13973,
            "13974": l13974,
            "13975": l13975,
            "490": l490,
            "491": l491,
            "492": l492,
        }

        message = ""

        if functions.checkNotFound(re.search('attempting to find tunnel group for IP:(.+?)\n', userLog)) != "not found":
            peer = functions.checkNotFound(re.search('attempting to find tunnel group for IP:(.+?)\n', userLog))
        else:
            peer = functions.checkNotFound(re.search('attempting to find tunnel group for IP:(.+?)\n', userLog))

        # ==============================================
        # The Case check begin here
        # ==============================================

        # Case 106
        if logs["13967"] and logs["13968"] and logs["13969"] and logs["13970"] and logs["13971"] and logs["13972"]:
            message = "PSK mismatch, verify that both peers have matching PSKs"
        elif logs["13971"] and logs["13972"]:
            message = "No response to our authentication request, make sure that shared secrets match"
        # Case 107
        elif logs["13970"] and logs["13971"] and logs["13973"] and logs["13975"]:
            message = "Authentication failed because the authentication types between the peers do not match, make sure they are set to match PSK or Certificate."

        # Case 108
        elif logs["13975"] and logs["13968"] and logs["13970"] and logs["13971"] and logs["13974"]:
            message = "Authentication failed because of a pre-shared-key mismatch"

        elif logs["11919"] and logs["11920"] and logs["11921"] and logs["11922"] and logs["11923"]: # or logs["11925"]
            message = "Remote end sent no proposal chosen, verify phase 1 policies match"

        elif logs["11003"] and logs["11008"] and logs["11917"] and logs["11918"]:
            message = "tunnel-group for peer %s missing keys" % peer

        elif logs["13128"] and logs["13129"] and logs["13130"]:


            i = 1
            espCompare1 = ""
            constEspCompare1 = re.search('Received Policies:\nESP: Proposal 1:  (.+?)\n', userLog)
            espCompare2 = []
            espProposal = re.search('Expected Policies:\nESP: Proposal 0:  (.+?)\n', userLog)
            if espProposal is not None:
                espCompare2.append(espProposal.group(1))

            while espProposal is not None:
                i = i+1
                espProposal = re.search('%s\n\n\nESP: Proposal %i:  (.+?)\n' % (espProposal.group(1), i), userLog)
                if espProposal is not None:
                    espCompare2.append(espProposal.group(1))

            compare1 = ""
            constCompare1 = re.search('Received Policies:\nProposal 1:  (.+?)\n', userLog)
            compare2 = []
            proposals = re.search('Expected Policies:\nProposal %i:  (.+?)\n' % i, userLog)
            if proposals is not None:
                compare2.append(proposals.group(1))

            while proposals is not None:
                i = i+1
                proposals = re.search('%s\n\nProposal %i:  (.+?)\n' % (proposals.group(1), i), userLog)
                if proposals is not None:
                    compare2.append(proposals.group(1))

            
            if constCompare1 is not None:
                for i, item in enumerate(compare2):
                    compare1 = constCompare1.group(1).split(" ")
                    compare2 = item.split(" ")
                    message = message + "\nPhase %i policy mismatch in: " % i
                    if compare1[0] != compare2[0]:
                        message = message + "ENCRYPTION" + " " + compare2[0] + "; "

                    if compare1[1] != compare2[1]:
                        message = message + "PRF" + " " + compare2[1] + "; "

                    if compare1[2] != compare2[2]:
                        message = message + "HASH" + " " + compare2[2] + "; "

                    if  "%s %s" % (compare1[3], compare1[4]) != "%s %s" % (compare2[3], compare2[4]):
                        message = message + "DH Group" + " " + compare2[3] + "; "
                    
            
            if(constEspCompare1 is not None):
                compare1 = constEspCompare1.group(1).split(" ")

                message = message + "\nPhase 2 policy mismatch in transform set: \n\n"
                message = message + "Recieved Encryption: " + compare1[0] + ", Hash: "+ compare1[1] +"\n"
                
                for i, item in enumerate(espCompare2):
                    compare2 = item.split(" ")
                    if compare1[0] != compare2[0]:
                        message = message + "TSet %i mismatch Encryption:  %s" % (i+1, compare2[0])
                    elif compare1[1] != compare2[1]:
                        message = message + "TSet %i mismatch Hash:  %s" % (i+1, compare2[1])
                    # else: #compare1[0] != compare2[0] and compare1[1] != compare2[1]:
                    #      message = message + "Transform set mismatch on phase 2, verify that ENCRYPTION and HASH match"
                if len(espCompare2) == 0:
                    message = "Phase 2 mismatch, verify that on the crypto map configuration the proper peer IP, ACLs and transform sets are configured"
            else:
                message = "Phase 2 mismatch, verify that on the crypto map configuration the proper peer IP, ACLs and transform sets are configured"

        elif logs["11003"] and logs["11917"] and logs["11918"] :
            message = "tunnel-group for peer %s missing keys" % peer

        # Case 105
        elif logs["13065"] and logs["13966"]:
            message = "Remote end not replying to UDP 500 init message, possible device in betwen blocking comunication or remote end configure for the wrong peer"

        elif logs["11904"] and logs["11907"]:
            message = "Tunnel-group not configured, verify there is a tunnel-group configured for IP %s" % peer

        # Case 111
        elif logs["490"] and logs["491"] :
            message = "Phase 2 mismatch, verify that on the crypto map configuration the proper peer IP, ACLs and transform sets are configured"

        # Case 109
        elif logs["13931"] and logs["13932"] :
            message = "Failure on Phase 1 as initiator, make sure ikev2 policies match as well as preshared key values. Or collect the debug as responder for a more detailed analysis."

        # Case 110
        elif logs["492"]:
            message = "Crypto map <VARIABLE1> seq <SEQ> is incomplete due to <VARIABLE2>"

        return message


# ch = CheckCase('../logs/TSet_Mismatch_responder.txt')
# print(ch.extractInfo())