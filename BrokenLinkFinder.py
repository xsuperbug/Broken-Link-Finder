from burp import IBurpExtender, IScannerCheck, IScanIssue, ITab
from java.io import PrintWriter
from java.net import URL
from java.util import ArrayList, List
from java.util.regex import Matcher, Pattern
import binascii
import base64
import re
from javax import swing
from java.awt import Font, Color
from threading import Thread
from array import array
from java.awt import EventQueue
from java.lang import Runnable
from thread import start_new_thread
from javax.swing import JFileChooser
from requests import get, post
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Run(Runnable):
    def __init__(self, runner):
        self.runner = runner

    def run(self):
        self.runner()


blacklist = ['telemetry', 'google-analytics', 'report-uri.cloudflare.com', 'www.w3.org', 'schema.org']
extension_blacklist = ['.jpg', '.png', '.jpeg', '.svg', '.woff2', '.woff', '.gif', '.pdf', '.eot', '.ttf', '.css',
                       '.gif']


class BurpExtender(IBurpExtender, IScannerCheck, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Broken Link Finder")

        callbacks.issueAlert("Broken Link Finder Passive Scanner enabled")

        stdout = PrintWriter(callbacks.getStdout(), True)
        stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.registerScannerCheck(self)
        self.initUI()
        self.callbacks.addSuiteTab(self)

        print("Broken Link Finder is loaded.")
        print("Copyright (c) 2021")
        self.outputTxtArea.setText("Broken Link Finder is loaded." + "\n" + "Copyright (c) 2021" + "\n")

    def initUI(self):
        self.tab = swing.JPanel()

        self.outputLabel = swing.JLabel("Logs:")
        self.outputLabel.setFont(Font("Tahoma", Font.BOLD, 14))
        self.outputLabel.setForeground(Color(255, 102, 52))
        self.logPane = swing.JScrollPane()
        self.outputTxtArea = swing.JTextArea()
        self.outputTxtArea.setFont(Font("Consolas", Font.PLAIN, 12))
        self.outputTxtArea.setLineWrap(True)
        self.logPane.setViewportView(self.outputTxtArea)
        self.clearBtn = swing.JButton("Clear Log", actionPerformed=self.clearLog)
        self.exportBtn = swing.JButton("Export Log", actionPerformed=self.exportLog)
        self.parentFrm = swing.JFileChooser()

        layout = swing.GroupLayout(self.tab)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
        self.tab.setLayout(layout)

        layout.setHorizontalGroup(
            layout.createParallelGroup()
                .addGroup(layout.createSequentialGroup()
                          .addGroup(layout.createParallelGroup()
                                    .addComponent(self.outputLabel)
                                    .addComponent(self.logPane)
                                    .addComponent(self.clearBtn)
                                    .addComponent(self.exportBtn)
                                    )
                          )
        )

        layout.setVerticalGroup(
            layout.createParallelGroup()
                .addGroup(layout.createParallelGroup()
                          .addGroup(layout.createSequentialGroup()
                                    .addComponent(self.outputLabel)
                                    .addComponent(self.logPane)
                                    .addComponent(self.clearBtn)
                                    .addComponent(self.exportBtn)
                                    )
                          )
        )

    def getTabCaption(self):
        return "Broken Link Finder"

    def getUiComponent(self):
        return self.tab

    def clearLog(self, event):
        self.outputTxtArea.setText("Broken Link Finder is loaded." + "\n" + "Copyright (c) 2021" + "\n")

    def exportLog(self, event):
        chooseFile = JFileChooser()
        ret = chooseFile.showDialog(self.logPane, "Choose file")
        filename = chooseFile.getSelectedFile().getCanonicalPath()
        open(filename, 'w', 0).write(self.outputTxtArea.text)

    def doActiveScan(self, ihrr, event):
        pass

    def github_check(self, domain):
        username = str(domain[2])[1:]
        githubHeader = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:90.0) Gecko/20100101 Firefox/90.0',
            'Connection': 'close'}
        try:
            gwresult = get('https://github.com/' + username, verify=False, headers=githubHeader).status_code
            if gwresult != 200:
                self.outputTxtArea.append("\n[+] Possible GitHub TakeOver https://github.com/" + username)
            else:
                self.outputTxtArea.append("\n[-] GitHub - @" + username + " is checked but it isn't available.")
        except:
            self.outputTxtArea.append("\n[-] GitHub - @" + username + " is NOT checked.")

    def twitter_check(self, domain):
        username = str(domain[2])[1:]
        tokenHeader = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Connection': 'close',
            'Authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA'}
        xguesttokenreq = post('https://api.twitter.com/1.1/guest/activate.json', verify=False, headers=tokenHeader)
        if xguesttokenreq.status_code == 200:
            xguesttoken = xguesttokenreq.text.split(':')[1][1:].split('"')[0]
            twitterHeader = {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0',
                'Content-Type': 'application/json', 'X-Guest-Token': xguesttoken, 'Connection': 'close',
                'Authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA'}
            try:
                twresult = get(
                    'https://twitter.com/i/api/graphql/4ti9aL9m_1Rb-QVTuO5QYw/UserByScreenNameWithoutResults?variables=%7B%22screen_name%22%3A%22' + username + '%22%2C%22withHighlightedLabel%22%3Atrue%7D',
                    verify=False, headers=twitterHeader).text
                if 'not found",' in twresult:
                    self.outputTxtArea.append("\n[+] Possible Twitter TakeOver https://twitter.com/" + username)
                else:
                    self.outputTxtArea.append("\n[-] Twitter - @" + username + " is checked but it isn't available.")
            except:
                self.outputTxtArea.append("\n[*] Twitter - @" + username + " is NOT checked!")
        else:
            self.outputTxtArea.append("\n[*] Twitter - @" + username + " is NOT checked!")

    def twitch_check(self, domain):
        username = str(domain[2])[1:]
        twitchHeader = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Client-Id': 'kimne78kx3ncx6brgo4mv6wki5h1ko', 'Connection': 'close'}
        twData = '''{"operationName": "PlaybackAccessToken_Template", "query": "query PlaybackAccessToken_Template($login: String!, $isLive: Boolean!, $vodID: ID!, $isVod: Boolean!, $playerType: String!) {  streamPlaybackAccessToken(channelName: $login, params: {platform: \\"web\\", playerBackend: \\"mediaplayer\\", playerType: $playerType}) @include(if: $isLive) {    value    signature    __typename  }  videoPlaybackAccessToken(id: $vodID, params: {platform: \\"web\\", playerBackend: \\"mediaplayer\\", playerType: $playerType}) @include(if: $isVod) {    value    signature    __typename  }}", "variables": {"isLive":   true, "login":"'''+username+'''", "isVod": false, "vodID": "", "playerType": "site"}}'''
        try:
            twresult = post('https://gql.twitch.tv/gql', verify=False, headers=twitchHeader, data=twData).text
            if 'signature' not in twresult:
                self.outputTxtArea.append("\n[+] Possible Twitch TakeOver https://twitch.tv/" + username)
            else:
                self.outputTxtArea.append("\n[-] Twitch - @" + username + " is checked but it isn't available.")
        except:
            self.outputTxtArea.append("\n[*] Twitch - @" + username + " is NOT checked!")

    def tumblr_check(self, domain):
        if len(domain) > 3:
            tumblHeader = {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0',
                'Connection': 'close',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5', 'Accept-Encoding': 'gzip, deflate'}
            try:
                tumbresult = get("https://" + domain, verify=False, headers=tumblHeader)
                if tumbresult.status_code == 404:
                    self.outputTxtArea.append('\n[+] Possible Tumblr TakeOver https://' + domain)
                else:
                    self.outputTxtArea.append("\n[-] Tumblr - @" + domain + " is checked but it isn't available.")
            except:
                self.outputTxtArea.append("\n[-] Tumblr - @" + username + " is NOT checked.")

    def instagram_check(self, domain):
        username = str(domain[2])[1:]
        if len(username) > 3:
            instaHeader = {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0',
                'Connection': 'close', 'X-Csrftoken': 'j3syfE1L7Q7EnD44JBZkxsbtNRce9zR4',
                'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest'}
            postData = {'username': username}
            self.outputTxtArea.append(
                            '\n[+] Possible Instagram TakeOver https://www.instagram.com/' + username + '/')
            try:
                insresult = post('https://www.instagram.com/accounts/web_create_ajax/attempt/', data=postData,
                                 verify=False, headers=instaHeader)
                if insresult.status_code == 200:
                    if not "username_is_taken" in str(insresult.text):
                        self.outputTxtArea.append(
                            '\n[+] Possible Instagram TakeOver https://www.instagram.com/' + username + '/')
                else:
                    self.outputTxtArea.append("\n[-] Instagram - @" + username + " is checked but it isn't available.")
            except:
                self.outputTxtArea.append("\n[-] Instagram - @" + username + " is NOT checked.")

    def facebook_check(self, domain):
        username = str(domain[2])
        if len(username) > 3 and ('/' not in str(username) or '%2f' not in str(username) or '%2F' not in str(username)):
            fwHeader = {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0',
                'Connection': 'close'}
            try:
                fcresult = get('https://www.facebook.com' + username, verify=False).status_code
                if fcresult == 404:
                    self.outputTxtArea.append('\n[+] Possible Facebook TakeOver https://www.facebook.com' + username)
                else:
                    self.outputTxtArea.append("\n[-] Facebook - @" + username + " is checked but it isn't available.")
            except:
                self.outputTxtArea.append("\n[-] Facebook - @" + username + " is NOT checked.")

    def doPassiveScan(self, ihrr):
        regex = r'(http|ftp|https):\/\/([\w\-_]+(?:(?:\.[\w\-_]+)+))([\w\-\.,@?^=%&:/~\+#]*[\w\-\@?^=%&/~\+#])?'
        try:
            urlReq = ihrr.getUrl()
            if str(urlReq) != "" or str(urlReq) != " " or str(urlReq) != None:
                encoded_resp = binascii.b2a_base64(ihrr.getResponse())
                decoded_resp = base64.b64decode(encoded_resp)
                if str(decoded_resp) != None or str(decoded_resp) != "":
                    try:
                        domains = re.findall(regex, str(decoded_resp))
                        if len(domains) > 0:
                            for domain in domains:
                                donotpass = False
                                donotpass_extension = False
                                for blocked in blacklist:
                                    if str(blocked) == str(domain[1]):
                                        donotpass = True
                                        break
                                if donotpass == False:
                                    for eb in extension_blacklist:
                                        if eb in domain[2]:
                                            donotpass_extension = True
                                            break
                                    if not donotpass_extension:
                                        if 'assets.' not in str(domain[1]) or 'static.' not in str(domain[1]) or 'statics.' not in str(domain[1]):
                                            if 'twitter.com' in str(domain[1]):
                                                self.outputTxtArea.append("\n[!] https://" + domain[1] + domain[2] + " will be checked.")
                                                self.twitter_check(domain)
                                            elif 'instagram.com' in str(domain[1]):
                                                self.outputTxtArea.append("\n[!] https://" + domain[1] + domain[2] + " will be checked.")
                                                self.instagram_check(domain)
                                            elif 'facebook.com' in str(domain[1]):
                                                self.outputTxtArea.append("\n[!] https://" + domain[1] + domain[2] + " will be checked.")
                                                self.facebook_check(domain)
                                            elif 'github.com' in str(domain[1]):
                                                self.outputTxtArea.append("\n[!] https://" + domain[1] + domain[2] + " will be checked.")
                                                self.github_check(domain)
                                            elif 'twitch.tv' in str(domain[1]):
                                                self.outputTxtArea.append("\n[!] https://" + domain[1] + domain[2] + " will be checked.")
                                                self.twitch_check(domain)
                                            elif 'tumblr.com' in str(domain[1]) and 'www.' not in str(domain[1]):
                                                self.outputTxtArea.append("\n[!] https://" + domain[1] + domain[2] + " will be checked.")
                                                self.tumblr_check(domain[1])

                    except:
                        pass

        except UnicodeEncodeError:
            print("Error in URL decode.")

        return None

    def consolidateDuplicateIssues(self, isb, isa):
        return -1

    def extensionUnloaded(self):
        print("Broken Link Finder unloaded.")
        return


class SRI(IScanIssue, ITab):
    def __init__(self, reqres, helpers):
        self.helpers = helpers
        self.reqres = reqres

    def getHost(self):
        return self.reqres.getHost()

    def getPort(self):
        return self.reqres.getPort()

    def getProtocol(self):
        return self.reqres.getProtocol()

    def getUrl(self):
        return self.reqres.getUrl()

    def getIssueName(self):
        return "Broken Link Finder Found a Link"

    def getIssueType(self):
        return 0x08000000

    def getSeverity(self):
        return "Information"

    def getConfidence(self):
        return "Tentative"  # "Certain", "Firm" or "Tentative"

    def getIssueBackground(self):
        return str("A broken link is a web-page that can't be found or accessed by a user, for various reasons. Web servers will often return an error message when a user tries to access a broken link. Broken links are also often known as 'dead links' or 'link rots.'")

    def getRemediationBackground(self):
        return "This is an <b>informational</b> finding only.<br>"

    def getIssueDetail(self):
        return str("Burp Scanner has analysed the following domains for broken links: <b>"
                   "%s</b><br><br>" % (self.reqres.getUrl().toString()))

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        rra = [self.reqres]
        return rra

    def getHttpService(self):
        return self.reqres.getHttpService()


if __name__ in ('__main__', 'main'):
    EventQueue.invokeLater(Run(BurpExtender))
