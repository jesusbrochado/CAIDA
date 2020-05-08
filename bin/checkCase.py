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
        l13065 = functions.checkNotFoundCase(re.search('I_SPI=DCA635040E30A6A3 R_SPI=0000000000000000 (I) MsgID = 00000000 CurState: I_WAIT_INIT Event: EV_NO_EVENT', userLog))
        l13066 = functions.checkNotFoundCase(re.search('Retransmitting packet', userLog))

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
            "13065": l13065,
            "13066": l13066
        }


        if(logs["11919"] and logs["11920"] and logs["11921"] and logs["11922"] and logs["11923"]):
            print("Remote end sent no proposal chosen, verify phase 1 policies match")
        elif(logs["11003"] and logs["11008"] and logs["11917"] and logs["11918"]):
            print("tunnel-group for peer x.x.x.x missing keys") # Replace X for the true value
        elif(logs["11003"] and logs["11917"] and logs["11918"]):
            print("tunnel-group for peer x.x.x.x missing keys")
        elif(logs["13065"] and logs["13966"]):
            print("Remote end not replying to UDP 500 init message, possible device in betwen blocking comunication or remote end configure for the wrong peer")
        elif(logs["11904"] and logs["11907"]):
            print("Tunnel-group not configured, verify there is a tunnel-group configured for IP x.x.x.x") # Replace X for the true value
        elif(logs["10001"]):
            print("Is initiator")


ch = CheckCase('../pub/debugs/userlog.txt')
ch.extractInfo()
