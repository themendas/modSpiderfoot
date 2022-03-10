# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_modMnds
# Purpose:      SpiderFoot plug-in for creating new modules.
#
# Author:      Borja Vilaplana <borjavilaplana@gmail.com>
#
# Created:     07/12/2021
# Copyright:   (c) Borja Vilaplana @MNDS 2021
# Licence:     GPL
# -------------------------------------------------------------------------------


import json
from pprint import pprint

from netaddr import IPNetwork
import http.client

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_mnds(SpiderFootPlugin):
    # The module descriptor dictionary contains all the meta data about a module necessary
    # for users to understand...
    meta = {
        # Module name: A very short but human readable name for the module.
        'name': "Mnds Module",

        # Description: A sentence briefly describing the module.
        'summary': "This is an example module to help developers create their own SpiderFoot modules.",

        # Flags: Attributes about this module:
        #   - apikey: Needs an API key to function
        #   - slow: Can be slow to find information
        #   - errorprone: Might generate high false positives
        #   - invasive: Interrogates the target, might be intensive
        #   - tool: Runs an external tool to collect data
        'flags': ["Investigate", "Footprint", "Passive"],

        # Use cases: The use case(s) this module should be included in, options are Footprint, Investigate and Passive.
        #   - Passive means the user's scan target is not contacted at all
        #   - Footprint means that this module is useful when understanding the target's footprint on the Internet
        #   - Investigate means that this module is useful when investigating the danger/risk of a target
        'useCases': ["Passive"],

        # Categories: The categories this module belongs in, describing how it operates. Only the first category is
        # used for now.
        #   - Content Analysis: Analyses content found
        #   - Crawling and Scanning: Performs crawling or scanning of the target
        #   - DNS: Queries DNS
        #   - Leaks, Dumps and Breaches: Queries data dumps and breaches
        #   - Passive DNS: Analyses passive DNS sources
        #   - Public Registries: Queries open/public registries of information
        #   - Real World: Queries sources about the real world (addresses, names, etc.)
        #   - Reputation Systems: Queries systems that describe the reputation of other systems
        #   - Search Engines: Searches public search engines with data about the whole Internet
        #   - Secondary Networks: Queries information about participation on secondary networks, like Bitcoin
        #   - Social Media: Searches social media data sources
        'categories': ["Social Media"],

        # For tool modules, have some basic information about the tool.
        'toolDetails': {
            # The name of the toola
            'name': "Nmap",

            # Descriptive text about the tool
            'description': "Detailed descriptive text about the tool",

            # The website URL for the tool. In many cases this will also be the
            # repo, but no harm in duplicating it.
            'website': 'https://tool.org',

            # The repo where the code of the tool lives.
            'repository': 'https://github.com/author/tool'
        },

        # Information about the data source (if any) this module queries for data. For modules
        # that purley parse data from other modules (e.g. sfp_email), this may be omitted.
        'dataSource': {
            # The primary website URL for the data source.
            'website': "https://www.datasource.com",

            # The subscription model for this data source.
            # - FREE_NOAUTH_UNLIMITED: Completely free, no need to obtain an API key and no limits
            #                          imposed beyond throttling.
            # - FREE_NOAUTH_LIMITED:   Completely free, no need to obtain an API key however limits
            #                          are imposed and you need to register/pay to exceed them.
            # - FREE_AUTH_UNLIMITED: Completely free, however you must obtain an API key to access
            #                        the service with no limits imposed beyond throttling.
            # - FREE_AUTH_LIMITED: Completely free, however you must obtain an API key and limits
            #                      are imposed. You need to upgrade(pay) to exceed them.
            # - COMMERCIAL_ONLY: No free tier is available at all.
            # - PRIVATE_ONLY: Invite only. Usually for betas and similar programs.
            'model': "FREE_NOAUTH_LIMITED",

            # Links to additional information. May be omitted.
            'references': [
                "https://www.datasource.com/api-documentation"
            ],

            # If an API key is optional or required, information on how to obtain the API key.
            # Each array element is a step. Ensure URLs are full URLs so they can be linked
            # automatically in the UI.
            'apiKeyInstructions': [
                "Visit https://www.datasource.com",
                "Register a free account",
                "Click on 'Account Settings'",
                "Click on 'Developer'",
                "The API key is listed under 'Your API Key'"
            ],

            # URL of the favicon for the data source.
            'favIcon': "https://www.datasource.com/favicon.ico",

            # URL of the full-size logo for the data source.
            'logo': "https://www.datasource.com/logo.gif",

            # A paragraph or two about the data source.
            'description': "A paragraph of text with details about the data source / services. "
            "Keep things neat by breaking the text up across multiple lines as "
            "has been done here. If line breaks are needed for breaking up "
            "multiple paragraphs, use \n.",
        }
    }

    # Default options. Delete any options not applicable to this module. Descriptions for each option
    # are defined in optdescs below. Options won't show up in the UI if they don't have an entry in
    # optdescs. This can be useful when you want something configured in code but not by the user.
    #
    # Note that these are just dictionary entries. The logic for how you react to these settings
    # is entirely for you to define AND IMPLEMENT in this module - nothing comes for free! :)
    #
    # Look at other modules for examples for how these settings are handled and implemented.
    #
    opts = {
        # If the module needs an API key, ensure api_key is in the name so that it gets
        # picked up as such in the UI.
        'api_key': '',
        # If the module accepts CO_HOSTED_SITE as an event, it sometimes makes sense to make
        # that configurable since some users don't care about co-hosted sites.
        'checkcohosts': True,
        # As above, but for affiliates.
        'checkaffiliates': True,
        # As above, but for NETBLOCK_MEMBERs.
        'subnetlookup': False,
        # As abovem but for DOMAIN_PTR
        'netblocklookup': True,
        # If subnetlookup is true, what's the maximum size subnet to iterate through?
        'maxsubnet': 24,
        # As above but for netblocks owned.
        'maxnetblock': 24,
        # For modules reporting CO_HOSTED_SITE events, it makes sense to put a cap
        # on how many to return since a high number usually indicates hosting, and users
        # likely do not care about such cases.
        'maxcohost': 100,
        # When reporting hosts, perform DNS lookup to check if they still resolve, and
        # if not report INTERNET_NAME_UNRESOLVED instead, if appropriate.
        'verify': True,
        # If reporting co-hosted sites, consider a site co-hosted if its domain matches
        # the target?
        "cohostsamedomain": False
    }

    # Option descriptions. Delete any options not applicable to this module.
    optdescs = {
        "api_key": "63efd9d276msh943778d7bf0c9bap13a292jsn1798bf91ad2f",
        'checkcohosts': "Check co-hosted sites?",
        'checkaffiliates': "Check affiliates?",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'subnetlookup': "Look up all IPs on subnets which your target is a part of?",
        'maxsubnet': "If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'maxcohost': "Stop reporting co-hosted sites after this many are found, as it would likely indicate web hosting.",
        "cohostsamedomain": "Treat co-hosted sites on the same target domain as co-hosting?",
        'verify': 'Verify that any hostnames found on the target domain still resolve?'

    }

    # Tracking results can be helpful to avoid reporting/processing duplicates
    results = None

    # Tracking the error state of the module can be useful to detect when a third party
    # has failed and you don't wish to process any more events.
    errorState = False


    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        # self.tempStorage() basically returns a dict(), but we use self.tempStorage()
        # instead since on SpiderFoot HX, different mechanisms are used to persist
        # data for load distribution, avoiding excess memory consumption and fault
        # tolerance. This keeps modules transparently compatible with both versions.
        self.results = self.tempStorage()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        # The data source for a module is, by default, set to the module name.
        # If you want to override that, for instance in cases where the module
        # is purely processing data from other modules instead of producing
        # data itself, you can do so with the following. Note that this is only
        # utilised in SpiderFoot HX and not the open source version.
        self.__dataSource__ = "Ptr DNS Resolve"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # For a list of all events, check spiderfoot/db.py.
    def watchedEvents(self):
        return ["IP_ADDRESS"]

    # What events this module produces
    def producedEvents(self):
        return ["risk_level"]

    # When querying third parties, it's best to have a dedicated function
    # to do so and avoid putting it in handleEvent()
    def query(self, qry):

        conn = http.client.HTTPSConnection("ip-reputation-geoip-and-detect-vpn.p.rapidapi.com")
        headers = {
            'x-rapidapi-host': "ip-reputation-geoip-and-detect-vpn.p.rapidapi.com",
            'x-rapidapi-key': "63efd9d276msh943778d7bf0c9bap13a292jsn1798bf91ad2f"
            }
        conn.request("GET", "/?ip=" + qry, headers=headers)
        res = conn.getresponse()

        data = res.read()
        datum = data.decode("utf-8")


                 # Report when unexpected things happen:
        # - debug(message) if it's only for debugging (user will see this if debugging is enabled)
        # - info(message) if it's not a bad thing
        # - error(message) if it's a bad thing and should cause the scan to abort
        # - fatal(message) if it's a horrible thing and should kill SpiderFoot completely
        if datum is None:
            self.info(f"No existe ptr dsn sobre {qry}")
            return None

        # Always process external data which is expected to be in a specific format
        # with try/except since we cannot trust the data is formatted as intended.
        try:
            return json.loads(datum)
        except Exception as e:
            self.error(f"Error processing JSON response from SHODAN: {e}")

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        # The three most used fields in SpiderFootEvent are:
        # event.eventType - the event type, e.g. INTERNET_NAME, IP_ADDRESS, etc.
        # event.module - the name of the module that generated the event, e.g. sfp_dnsresolve
        # event.data - the actual data, e.g. 127.0.0.1. This can sometimes be megabytes in size (e.g. a PDF)
        eventName = event.eventType
        eventData = event.data

        # Once we are in this state, return immediately.
        if self.errorState:
            return
        # Don't be recursive for names
        # if srcModuleName in ["sfp_mnds2"] and "_NAME" in eventName:
        #     return

        # self.debug(f"Received event, {eventName}, from {srcModuleName}")

        # Check if the module has already analysed this event data.
        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        # Add the event data to results dictionary to prevent duplicate queries.
        # If eventData might be something large, set the key to a hash
        # of the value instead of the value, to avoid memory abuse.
        self.results[eventData] = True

        qrylist = list()

        # if eventName == 'IP_ADDRESS':
        #     for ipaddr in self.sf.resolveIP(eventData):
        #         qrylist.append(str(ipaddr))
        #         self.results[str(ipaddr)] = True
        # else:
        qrylist.append(eventData)

        # We now have a set of hosts/IPs to do something with.
        for addr in qrylist:
            # Perform the query to the third party; in this case for each IP
            # being queried.
            rec = self.query(addr)

            # Handle the response being empty/failing
            if rec is None:
                continue

            pevent = event

            evt = SpiderFootEvent("TARGET_WEB_CONTENT", str(rec), self.__name__, pevent)
            self.notifyListeners(evt)

            if self.checkForStop():
                return

            if event.moduleDataSource:
                evt.moduleDataSource = event.moduleDataSource
            else:
                evt.moduleDataSource = "Unknown"

            os = rec.get('os')
            if os:
                evt = SpiderFootEvent("OPERATING_SYSTEM", f"{os} ({addr})", self.__name__, pevent)
                self.notifyListeners(evt)

# End of sfp_mnds class
