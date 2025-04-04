# -*- coding: utf-8 -*-
from burp import IBurpExtender, IContextMenuFactory
from java.util import ArrayList
from javax.swing import JMenuItem
import json
import urllib2
import threading

class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("GPT API Analyzer")
        self._callbacks.registerContextMenuFactory(self)
        self._stdout = callbacks.getStdout()
        self._stderr = callbacks.getStderr()
        self._server_url = "http://localhost:5000/analyze"  # Default endpoint

        print("GPT API Analyzer extension loaded")

    def createMenuItems(self, invocation):
        menu = ArrayList()
        messageInfo = invocation.getSelectedMessages()

        if messageInfo:
            menuItem = JMenuItem("Analyze with GPT", actionPerformed=lambda x: self.analyze_with_gpt(messageInfo[0]))
            menu.add(menuItem)

        return menu

    def analyze_with_gpt(self, messageInfo):
        request_info = self._helpers.analyzeRequest(messageInfo)
        url = request_info.getUrl()
        method = request_info.getMethod()
        headers = [str(h) for h in request_info.getHeaders()]
        body = messageInfo.getRequest()[request_info.getBodyOffset():].tostring()

        data = {
            "method": method,
            "path": str(url.getPath()),
            "headers": headers,
            "body": body
        }

        print("Sending to GPT:", data["path"])
        threading.Thread(target=self.send_to_server, args=(data,)).start()

    def send_to_server(self, data):
        try:
            req = urllib2.Request(self._server_url, json.dumps(data), {'Content-Type': 'application/json'})
            response = urllib2.urlopen(req)
            result = response.read()
            print("GPT response:", result)
        except Exception as e:
            print("Error contacting GPT backend:", e)
