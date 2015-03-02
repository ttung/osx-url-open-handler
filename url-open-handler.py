#!/usr/bin/python

import os.path
import struct
import subprocess
import re
import urlparse

from objc import YES, NO, nil, signature
from AppKit import *
from Foundation import *
from PyObjCTools import AppHelper

import ConfigParser


class RuleEvaluator:
    TTL_DEFAULT = 10
    BROWSER_MAP = {
        'safari': '/Applications/Safari.app',
        'chrome': '/Applications/Google Chrome.app',
    }
    SCHEME_KEY = 'scheme'
    HOSTNAME_KEY = 'hostname'
    PATH_KEY = 'path'
    QUERY_SELECT_KEY = 'query_select'
    ACTION_KEY = 'action'

    ACTION_UNWRAP_QUERY = 'unwrap'

    def __init__(self):
        self.config = ConfigParser.ConfigParser()
        self.config.read(os.path.expanduser('~/Library/Preferences/url-open-handler.cfg'))

    def silent_get(self, section, option):
        if self.config.has_option(section, option):
            return self.config.get(section, option)
        return None

    def run_rule_against_parsed_url(self, url, parsed, ttl, section):
        config_scheme = self.silent_get(section, RuleEvaluator.SCHEME_KEY)
        config_hostname = self.silent_get(section, RuleEvaluator.HOSTNAME_KEY)
        config_path = self.silent_get(section, RuleEvaluator.PATH_KEY)
        config_query_select = self.silent_get(section, RuleEvaluator.QUERY_SELECT_KEY)
        config_action = self.config.get(section, RuleEvaluator.ACTION_KEY)

        if config_scheme is not None and parsed.scheme.lower() != config_scheme.lower():
            return False
        if config_hostname is not None and parsed.hostname.lower() != config_hostname.lower():
            return False
        if config_path is not None and parsed.path != config_path:
            return False

        # we have a match!
        if config_action in RuleEvaluator.BROWSER_MAP:
            args = ['/usr/bin/open', '-a', RuleEvaluator.BROWSER_MAP[config_action], url]
            subprocess.call(args)
            return True
        elif config_action == RuleEvaluator.ACTION_UNWRAP_QUERY:
            qs_parsed = urlparse.parse_qs(parsed.query)
            if config_query_select in qs_parsed:
                return self.run_rules_against_parsed_url(qs_parsed[config_query_select][0], ttl - 1)

    def run_rules_against_parsed_url(self, url, ttl=TTL_DEFAULT):
        parsed = urlparse.urlparse(url)
        if ttl == 0:
            NSLog("Unable to handle url (ttl expired)")
            return False

        for section in self.config.sections():
            if self.run_rule_against_parsed_url(url, parsed, ttl, section):
                return True

        return self.run_rule_against_parsed_url(url, parsed, ttl, 'DEFAULT')


class AppDelegate(NSObject):

    def applicationWillFinishLaunching_(self, notification):
        man = NSAppleEventManager.sharedAppleEventManager()
        man.setEventHandler_andSelector_forEventClass_andEventID_(
            self,
            "openURL:withReplyEvent:",
            struct.unpack(">i", "GURL")[0],
            struct.unpack(">i", "GURL")[0])
        man.setEventHandler_andSelector_forEventClass_andEventID_(
            self,
            "openURL:withReplyEvent:",
            struct.unpack(">i", "WWW!")[0],
            struct.unpack(">i", "OURL")[0])
        NSLog("Registered URL handler")

    @signature('v@:@@')
    def openURL_withReplyEvent_(self, event, replyEvent):
        keyDirectObject = struct.unpack(">i", "----")[0]
        url = event.paramDescriptorForKeyword_(keyDirectObject).stringValue().decode('utf8')

        NSLog("Received URL: %@", url)
        evaluator = RuleEvaluator()
        try:
            if evaluator.run_rules_against_parsed_url(url) == False:
                NSLog("Unable to handle URL: %@", url)
        except Exception as ex:
            NSLog("got an exc: %@", ex)
            raise

def main():
    app = NSApplication.sharedApplication()

    delegate = AppDelegate.alloc().init()
    app.setDelegate_(delegate)

    AppHelper.runEventLoop()

if __name__ == '__main__':
    main()
