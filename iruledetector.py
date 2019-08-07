# -*- coding: utf-8 -*-
# Burp iRulesDetector Extension
# Christoffer Jerkeby F-Secure

try:
    from burp import IBurpExtender
    from burp import IScannerCheck
    from burp import IExtensionStateListener
    from burp import IHttpRequestResponse
    from burp import IScanIssue
    from burp import IScannerInsertionPointProvider
    from burp import IScannerInsertionPoint
    from burp import IExtensionHelpers
    from burp import IParameter

    from string import Template
    import array
    import uuid
    import re

except ImportError:
    print("Failed to load dependencies. This issue maybe caused"\
          "by using an unstable Jython version.")

# TODO: Write a nicer reporting template text

VERSION = "0.3"
VERSIONNAME = "adisposse"
EXTENDERNAME = "iRules Injection Detector"

class BurpExtender(IBurpExtender, IScannerCheck, IExtensionStateListener, IHttpRequestResponse):
    def registerExtenderCallbacks(self, callbacks):
        """Register the callbacks for the extender."""
        print("Loading...")
        self._callbacks = callbacks
        self._callbacks.setExtensionName("iRules injector and detector")
        self._callbacks.registerScannerCheck(self)
        self._callbacks.registerExtensionStateListener(self)
        self._helpers = callbacks.getHelpers()
        self.servername = "BigIP"
        self.attackpatterns = [Template("{[TCP::respond $token]}"),
                               Template("[TCP::respond $token]"),
                               Template("\\[TCP::respond $token\\]"),
                               Template("; TCP::respond $token"),
                               Template("-crash")]
        print("Loaded {} v{} ({})!".format(EXTENDERNAME, VERSION, VERSIONNAME))
        return

    def extensionUnloaded(self):
        """Unload the extension."""
        print("{} unloaded.".format(EXTENDERNAME))
        return

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """
        Perform an active scan by injecting a iRule string in every possible field and
        check for a known resulting value.
        Return list of ScanIssues.
        """
        print("Initializing Active scan for iRule injection.")
        vulns = []
        for pattern in self.attackpatterns:
            token = str(uuid.uuid1())
            vuln = self.inject(insertionPoint,
                               baseRequestResponse,
                               pattern,
                               token)
            if vuln:
                print(vuln)
                vulns.append(vuln)

        if len(vulns) == 0:
            return None
        return vulns

    def inject(self, insertionPoint, baseRequestResponse, pattern, token):
        """
        Insert self.attackpatterns in insertionPoint and send request.
        If the response contains the token return the insertionPoint highlight.
        Return ScanIssue report for the requested vulnerability or None.
        """
        issuename = "BIG-IP F5 command injection."
        issuelevel = "High"
        issuedetail = "The F5 iRule service is handling user input in an insecure way " \
                      "and can be remote controlled."
        issuebackground = "An input variable is not properly quoted and its content is " \
                          "executed during expansion."
        issueremediation = "Audit the iRule code for methods that use quotes (\") in " \
                           "argument list, replace them with curly bracket {}."
        issueconfidence = "Certain"

        pattern = pattern.substitute(token=token)

        # This ugly sh*t is done because IScannerInsertionPointProvider is incomplete, prove me wrong!
        template = "X" * len(pattern)
        checkRequest = insertionPoint.buildRequest(bytearray(template))
        strRequest = self._helpers.bytesToString(checkRequest)
        strRequest = re.sub(template, pattern, strRequest, 1)
        checkRequest = self._helpers.stringToBytes(strRequest)

        checkRequestResponse = self._callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), checkRequest)

        response = checkRequestResponse.getResponse()

        if not response:
            # This can be a sign of a half-successful command injection!
            # Most probably an attempt need to be done with or without curly brackets.
            # TODO: Report this issue or make smart choice to change strategy,
            #  the later can cause infinite loops
            # Timeout or conneciton reset often means syntax error or that a long request was made
            # sometimes BIGIP crashes after to multiple injecitons.
            return None

        if not self._starts_with(response, token):
            return None

        matches = self._get_matches(checkRequestResponse.getResponse(), token)
        offset = [insertionPoint.getPayloadOffsets(pattern)]
        marker = self._callbacks.applyMarkers(checkRequestResponse,
                                              offset,
                                              matches)

        return ScanIssue(baseRequestResponse.getHttpService(),
                         self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                         issuename, issuelevel, issuedetail, issuebackground,
                         issueremediation, issueconfidence, [marker])

    def _starts_with(self, response, match):
        """
        Check if a response byte array starts with match string.
        Return true if it does.
        """
        try:
            response = response[:len(match)]
            response = self._helpers.bytesToString(response)
        except UnicodeError as e:
            print("Unicode Error: {}".format(e))
            return False
        if response == match:
            return True
        return False

    def doPassiveScan(self, baseRequestResponse):
        """
        Look for a server header that the string BIG-IP
        Return a ScanIssue if a Bigip header is found in the baseRequestResponse.
        """
        print("Initiating a passive scan with BIG-IP server name detector.")
        if self.isBigip(baseRequestResponse):
            issuename = "BigIP server header detected"
            issuelevel = "Information"
            issuedetail = "The server is running behind a BIG-IP F5 reverse proxy. "
            issuebackground = "The server header is set to BigIP on requests that are" \
                              " replied to using a HTTP::respond function by the F5."
            issueremediation = "The BigIP server header can be removed using a custom " \
                               " header in the HTTP::respond method."
            issueconfidence = "Certain"
            matches = self._get_matches(baseRequestResponse.getResponse(), self.servername)
            marker = self._callbacks.applyMarkers(baseRequestResponse, None, matches)
            return [ScanIssue(baseRequestResponse.getHttpService(),
                             self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                             issuename, issuelevel, issuedetail, issuebackground,
                             issueremediation, issueconfidence, [marker])]
        return None

    def isBigip(self, requestResponse):
        """
        Checks for a server string in header containing BIG-IP
        """
        print("Running passive scan on {}".format(self._helpers.analyzeRequest(requestResponse).getUrl()))
        response = requestResponse.getResponse()
        headers = self._helpers.analyzeResponse(response).getHeaders()
        for header in headers:
            headername = header.split(':')[0].lower()
            if headername == "server":
                headervalue = header.split(':')[1].strip()
                if headervalue == self.servername:
                    return True
        return False

    def _get_matches(self, response, match):
        """
        Helper method to search a response for occurrences of a literal match string
        and return a list of start/end offsets.
        """
        matches = []
        start = 0
        reslen = len(response)
        matchlen = len(match)
        while start < reslen:
            start = self._helpers.indexOf(response, match, True, start, reslen)
            if start == -1:
                break
            matches.append(array.array('i', [start, start + matchlen]))
            start += matchlen

        return matches

class ScanIssue(IScanIssue):
    def __init__(self, httpservice, url, name, severity, detailmsg, background, remediation, confidence, requests):
        self._url = url
        self._httpservice = httpservice
        self._name = name
        self._severity = severity
        self._detailmsg = detailmsg
        self._issuebackground = background
        self._issueremediation = remediation
        self._confidence = confidence
        self._httpmsgs = requests

    def getUrl(self):
        return self._url

    def getHttpMessages(self):
        return self._httpmsgs

    def getHttpService(self):
        return self._httpservice

    def getRemediationDetail(self):
        return None

    def getIssueDetail(self):
        return self._detailmsg

    def getIssueBackground(self):
        return self._issuebackground

    def getRemediationBackground(self):
        return self._issueremediation

    def getIssueType(self):
        return 0

    def getIssueName(self):
        return self._name

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence
