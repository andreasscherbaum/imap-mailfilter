#!/usr/bin/env python3
#
# filter emails in IMAP accounts
#
# written by: Andreas Scherbaum <andreas@scherbaum.la>
#


import re
import os
import stat
import sys
if sys.version_info[0] < 3:
    reload(sys)
    sys.setdefaultencoding('utf8')
import logging
import tempfile
import argparse
import yaml
import string
import sqlite3
import datetime
import atexit
import shlex
import imaplib
imaplib._MAXLINE = 10000000
import email
import email.header
from email.parser import HeaderParser
from email.parser import Parser
import email
import random

import gzip
import zlib
from subprocess import Popen
try:
    from urlparse import urljoin # Python2
except ImportError:
    from urllib.parse import urljoin # Python3

import smtplib
from email.mime.text import MIMEText

from html.parser import HTMLParser

import requests
from socket import error as SocketError
import errno


sys.path.insert(0, os.path.abspath('./python-twitter'));
# the module name "twitter" will clash with something preinstalled
# we load the module in the "python-twitter" directory, with a different alias name
# https://github.com/bear/python-twitter
import twitter as TW



# start with 'info', can be overriden by '-q' later on
logging.basicConfig(level = logging.INFO,
		    format = '%(levelname)s: %(message)s')






#######################################################################
# Message Parser class

class MyMessageParser(HTMLParser):

    def __init__(self):
        HTMLParser.__init__(self)


    def get_list():
        return self._links


    def parse_message(self, message):
        self._links = []
        self.reset()
        parser = Parser()
        parsed = parser.parsestr(str(message), headersonly=False)
        if (parsed.is_multipart() is True):
            for part in parsed.walk():
                if (part.get_content_type() == "multipart" or part.get_content_type() == "multipart/alternative"):
                    continue
                if (part.get_content_type() == "text/plain"):
                    self.find_urls(str(part.get_payload(decode = True)))
                if (part.get_content_type() == "text/html"):
                    self.feed(str(part.get_payload(decode = True)))
        else:
            if (parsed.get_content_type() == "text/plain"):
                self.find_urls(str(parsed.get_payload(decode = True)))
            if (parsed.get_content_type() == "text/html"):
                self.feed(str(parsed.get_payload(decode = True)))
        self._links = list(dict.fromkeys(self._links))
        return self._links


    def handle_starttag(self, tag, attrs):
        #print("Encountered a start tag:", tag)
        if (tag == "a"):
            #print("Encountered a start tag:", tag)
            for name, value in attrs:
                if (name == "href"):
                    #print(name, value)
                    #print(name, "=", value)
                    # the values are not exactly clean all the time
                    if (value.startswith('=')):
                        value = value[len('='):]
                    if (value.startswith('3D')):
                        value = value[len('3D'):]
                    if (value.startswith('"')):
                        value = value[len('"'):]
                    self._links.append(str(value))

    #def handle_endtag(self, tag):
    #    print("Encountered an end tag:", tag)

    #def handle_data(self, data):
    #    print("Encountered some data:", data)


    def find_urls(self, message):
        urls = re.findall('https?://[^\r\n\t\s\\\\]+', message)
        for u in urls:
            self._links.append(str(u))


# end HTMLParser class
#######################################################################






#######################################################################
# Config class

class Config:

    def __init__(self):
        self.__cmdline_read = 0
        self.__configfile_read = 0
        self.arguments = False
        self.argument_parser = False
        self.configfile = False
        self.config = False
        self.output_help = True
        self.retweets = {}

        if (os.environ.get('HOME') is None):
            logging.error("$HOME is not set!")
            sys.exit(1)
        if (os.path.isdir(os.environ.get('HOME')) is False):
            logging.error("$HOME does not point to a directory!")
            sys.exit(1)



    # config_help()
    #
    # flag if help shall be printed
    #
    # parameter:
    #  - self
    #  - True/False
    # return:
    #  none
    def config_help(self, config):
        if (config is False or config is True):
            self.output_help = config
        else:
            print("")
            print("invalid setting for config_help()")
            sys.exit(1)



    # print_help()
    #
    # print the help
    #
    # parameter:
    #  - self
    # return:
    #  none
    def print_help(self):
        if (self.output_help is True):
            self.argument_parser.print_help()



    # add_retweet()
    #
    # add to the retweet counter
    #
    # parameter:
    #  - self
    #  - name of Twitter account
    # return:
    #  none
    def add_retweet(self, name):
        if (name in self.retweets.keys()):
            self.retweets[name] += 1
        else:
            self.retweets[name] = 1



    # get_retweets()
    #
    # get number of current retweets for a Twitter account
    #
    # parameter:
    #  - self
    #  - name of Twitter account
    # return:
    #  - number of retweets in current run
    def get_retweets(self, name):
        if (name not in self.retweets.keys()):
            return 0
        return self.retweets[name]



    # set_retweets()
    #
    # set the number of current retweets for a Twitter account
    #
    # parameter:
    #  - self
    #  - name of Twitter account
    #  - new value
    # return:
    #  none
    def set_retweets(self, name, value):
        try:
            value = int(value)
            if (value < 0):
                raise ValueError
        except ValueError:
            logging.error("Value '%s' is not an integer" % (str(value)))
            sys.exit(1)
        self.retweets[name] = int(value)



    # parse_parameters()
    #
    # parse commandline parameters, fill in array with arguments
    #
    # parameter:
    #  - self
    # return:
    #  none
    def parse_parameters(self):
        parser = argparse.ArgumentParser(description = 'filter emails in IMAP accounts',
                                         add_help = False)
        self.argument_parser = parser
        parser.add_argument('--help', default = False, dest = 'help', action = 'store_true', help = 'show this help')
        parser.add_argument('-c', '--config', default = '', dest = 'config', help = 'configuration file')
        # store_true: store "True" if specified, otherwise store "False"
        # store_false: store "False" if specified, otherwise store "True"
        parser.add_argument('-v', '--verbose', default = False, dest = 'verbose', action = 'store_true', help = 'be more verbose')
        parser.add_argument('-q', '--quiet', default = False, dest = 'quiet', action = 'store_true', help = 'run quietly')


        # parse parameters
        args = parser.parse_args()

        if (args.help is True):
            self.print_help()
            sys.exit(0)

        if (args.verbose is True and args.quiet is True):
            self.print_help()
            print("")
            print("Error: --verbose and --quiet can't be set at the same time")
            sys.exit(1)

        if not (args.config):
            self.print_help()
            print("")
            print("Error: configfile is required")
            sys.exit(1)

        if (args.verbose is True):
            logging.getLogger().setLevel(logging.DEBUG)

        if (args.quiet is True):
            logging.getLogger().setLevel(logging.ERROR)

        self.__cmdline_read = 1
        self.arguments = args

        return



    # load_config()
    #
    # load configuration file (YAML)
    #
    # parameter:
    #  - self
    # return:
    #  none
    def load_config(self):
        if not (self.arguments.config):
            return

        logging.debug("config file: " + self.arguments.config)

        if (self.arguments.config and os.path.isfile(self.arguments.config) is False):
            self.print_help()
            print("")
            print("Error: --config is not a file")
            sys.exit(1)

        # the config file holds sensitive information, make sure it's not group/world readable
        st = os.stat(self.arguments.config)
        if (st.st_mode & stat.S_IRGRP or st.st_mode & stat.S_IROTH):
            self.print_help()
            print("")
            print("Error: --config must not be group or world readable")
            sys.exit(1)


        try:
            with open(self.arguments.config, 'r') as ymlcfg:
                config_file = yaml.safe_load(ymlcfg)
        except:
            print("")
            print("Error loading config file")
            sys.exit(1)


        # verify all account entries
        errors_in_config = False
        try:
            t = config_file['accounts']
        except KeyError:
            print("")
            print("Error: missing 'accounts' entry in config file")
            errors_in_config = True

        if (errors_in_config is True):
            sys.exit(1)


        self.configfile = config_file
        self.__configfile_read = 1

        return


# end Config class
#######################################################################






#######################################################################
# Database class

class Database:

    def __init__(self, config):
        self.config = config

        # database defaults to a hardcoded file
        self.connection = sqlite3.connect(os.path.join(os.environ.get('HOME'), '.imap-mailfilter', 'imap-mailfilter.sqlite'))
        self.connection.row_factory = sqlite3.Row
        # debugging
        #self.drop_tables()
        self.init_tables()
        #sys.exit(0);

        atexit.register(self.exit_handler)



    def exit_handler(self):
        self.connection.close()



    # init_tables()
    #
    # initialize all missing tables
    #
    # parameter:
    #  - self
    # return:
    #  none
    def init_tables(self):
        if (self.table_exist('seen_emails') is False):
            logging.debug("need to create table seen_emails")
            self.table_seen_emails()



    # drop_tables()
    #
    # drop all existing tables
    #
    # parameter:
    #  - self
    # return:
    #  none
    def drop_tables(self):
        if (self.table_exist('seen_emails') is True):
            logging.debug("drop table seen_emails")
            self.drop_table('seen_emails')




    # table_exist()
    #
    # verify if a table exists in the database
    #
    # parameter:
    #  - self
    #  - table name
    # return:
    #  - True/False
    def table_exist(self, table):
        query = "SELECT name FROM sqlite_master WHERE type='table' AND name=?"
        result = self.execute_one(query, [table])
        if (result is None):
            return False
        else:
            return True



    # drop_table()
    #
    # drop a specific table
    #
    # parameter:
    #  - self
    #  - table name
    # return:
    #  none
    def drop_table(self, table):
        # there is no sane way to quote identifiers in Python for SQLite
        # assume that the table name is safe, and that the author of this module
        # never uses funny table names
        query = 'DROP TABLE "%s"' % table
        self.execute_one(query, [])



    # run_query()
    #
    # execute a database query without parameters
    #
    # parameter:
    #  - self
    #  - query
    # return:
    #  none
    def run_query(self, query):
        cur = self.connection.cursor()
        cur.execute(query)
        self.connection.commit()



    # execute_one()
    #
    # execute a database query with parameters, return single result
    #
    # parameter:
    #  - self
    #  - query
    #  - list with parameters
    # return:
    #  - result
    def execute_one(self, query, param):
        cur = self.connection.cursor()

        cur.execute(query, param)
        result = cur.fetchone()

        self.connection.commit()
        return result



    # execute_query()
    #
    # execute a database query with parameters, return result set
    #
    # parameter:
    #  - self
    #  - query
    #  - list with parameters
    # return:
    #  - result set
    def execute_query(self, query, param):
        cur = self.connection.cursor()

        cur.execute(query, param)
        result = cur.fetchall()

        self.connection.commit()
        return result



    # table_seen_emails()
    #
    # create the 'seen_emails' table
    #
    # parameter:
    #  - self
    # return:
    #  none
    def table_seen_emails(self):
        query = """CREATE TABLE seen_emails (
                id INTEGER PRIMARY KEY NOT NULL,
                added_ts DATETIME DEFAULT CURRENT_TIMESTAMP,
                msgid TEXT NOT NULL,
                account TEXT NOT NULL,
                rule TEXT NOT NULL
                )"""
        self.run_query(query)



    # remember_msg_id()
    #
    # store Msg-ID
    #
    # parameter:
    #  - self
    #  - Msg-ID
    #  - Account
    #  - Rule name
    # return:
    #  none
    def remember_msg_id(self, msg_id, account, rule):
        if (self.msgid_seen_before(msg_id, account, rule) is True):
            return

        query = """INSERT INTO seen_emails
                               (msgid, account, rule)
                        VALUES (?, ?, ?)"""
        self.execute_one(query, [msg_id, account, rule])



    # msgid_seen_before()
    #
    # verify if a Msg-ID was seen before
    #
    # parameter:
    #  - self
    #  - Msg-ID
    #  - Account
    #  - Rule name
    # return:
    #  - True/False
    def msgid_seen_before(self, msg_id, account, rule):
        query = """SELECT *
                     FROM seen_emails
                    WHERE msgid = ?
                      AND account = ?
                      AND rule = ?"""

        res = self.execute_one(query, [msg_id, account, rule])
        if (res is None):
            # not in database
            return False
        else:
            return True



# end Database class
#######################################################################






#######################################################################
# IMAP class

class ImapConnection:

    def __init__(self, config, account_name, server, username, password, ssl = True):
        self.config = config
        self.account_name = account_name
        self.server = server
        self.username = username
        self.password = password
        self.ssl = ssl

        if (self.server == 'imap.gmail.com'):
            # required for flag operations like "delete" (move to trash instead)
            self.gmail = True
        else:
            self.gmail = False

        # open TCP connection
        error = False
        try:
            if (ssl is True):
                self.connection = imaplib.IMAP4_SSL(self.server)
            else:
                self.connection = imaplib.IMAP4(self.server)
        except TimeoutError:
            error = True
            logging.error("Connection '%s' timed out" % self.account_name)
            if (self.ssl is False):
                logging.info("Try using SSL mode instead")
        if (error is True):
            # outside of except block, else this would re-raise the exception
            raise imaplib.IMAP4.error("Connection '%s' timed out" % self.account_name)


        # login into IMAP server
        error = False
        try:
            resp, data = self.connection.login(self.username, self.password)
        except imaplib.IMAP4.error:
            logging.error("Invalid username/password combination for '%s'" % self.account_name)
            try:
                error = True
                self.connection.shutdown()
            except:
                pass

        if (error is True):
            raise imaplib.IMAP4.error("Invalid username/password combination for '%s'" % self.account_name)
        # should see an 'OK' response here
        if (resp != 'OK'):
            logging.error("Invalid response from IMAP server for '%s'" % self.account_name)
            try:
                self.connection.logout()
            except:
                pass
            raise imaplib.IMAP4.error("Invalid response from IMAP server for '%s'" % self.account_name)

        logging.debug("Connection for '%s' established" % self.account_name)

        # print the list of folders
        # print(self.connection.list())

        atexit.register(self.exit_handler)

        return



    # exit_handler()
    #
    # shutdown connection
    #
    # parameter:
    #  - self
    # return:
    #  none
    def exit_handler(self):
        try:
            self.connection.shutdown()
            self.connection.logout()
        except:
            pass



    # select_imap_folder()
    #
    # select a specific IMAP folder
    #
    # parameters:
    #  - self
    #  - folder name
    # return:
    #  - True/False
    def select_imap_folder(self, folder):
        # first check if the folder exists
        logging.debug("select IMAP folder: %s" % folder)
        folder_tmp = '"' + folder + '"'
        try:
            e = self.connection.status(folder_tmp, '(MESSAGES)')
        except imaplib.IMAP4.error:
            logging.error("Failed to fetch folder status")
            return False
        except SocketError:
            logging.error("Failed to fetch folder status")
            return False
        if (e[0] != 'OK'):
            logging.error("Selected folder (%s) does not exist" % folder)
            return False

        try:
            e = self.connection.select(folder_tmp)
        except imaplib.IMAP4.error:
            logging.error("Failed to select folder: %s" % folder_tmp)
            return False
        if (e[0] != 'OK'):
            logging.error("Can't select folder (%s)" % folder)
            return False

        return True



    # search()
    #
    # search in current IMAP folder
    #
    # parameters:
    #  - self
    #  - search option
    #  - search criteria
    #  - additional UIDs to limit the search
    # return:
    #  - list with uids, or empty list
    def search(self, what, criteria, uids = []):
        # make sure the criteria is plain ascii, as IMAP does not support searching for UTF-8
        try:
            criteria.encode('ascii')
        except UnicodeEncodeError:
            logging.error("Can't support UTF-8 in search criterta: %s", criteria)
            return []


        logging.debug("search (before lexer): %s / %s" % (what, criteria))
        # split and parse all strings
        criteria = shlex.split(criteria)
        logging.debug("search (after lexer): %s / %s" % (what, criteria))


        # loop over the criteria and decide if each entry is a search criteria or a keyword
        # first get a list of results for each criteria
        last_op = ''
        for search in criteria:
            if (search == 'AND' or search == 'OR'):
                last_op = search
                continue
            if (search == 'NOT'):
                # last operation must be an AND
                if (last_op == 'AND'):
                    last_op = 'AND NOT'
                    continue
                else:
                    # invalid query
                    logging.error("NOT can only follow an AND: %s", criteria)
                    return []

            # this will search for messages in the currently selected folder
            # if a list with UIDs is specified, the search will be limited to this UIDs - hence further redefining the search
            search = what + ' "%s"' % search
            if (len(uids) > 0):
                search += ' UID %s' % ",".join(uids)
            logging.debug("partial search: " + str(search))
            try:
                result, messages = self.connection.uid('search', None, search)
            except KeyError:
                logging.error("Test")
                sys.exit(1)
            except imaplib.IMAP4.error:
                logging.error("Search failed!")
                sys.exit(1)

            uids_tmp = messages[0].split()
            uids_tmp = [x.decode() for x in uids_tmp]
            logging.debug("partial UIDs: " + str(uids_tmp))

            # handle results based on last found operation
            if (last_op == 'AND'):
                # this will only select the uids which are in both result sets
                new_uids = []
                for t in uids:
                    if (t in uids_tmp):
                        new_uids.append(t)
                uids = new_uids
            elif (last_op == 'OR'):
                # this will select the uids which are in either of the result sets
                for t in uids_tmp:
                    if (t not in uids):
                        uids.append(t)
            elif (last_op == 'AND NOT'):
                # this will only select the uids in the first result set which do not appear in the second set
                new_uids = []
                for t in uids:
                    if (t not in uids_tmp):
                        new_uids.append(t)
                uids = new_uids
            else:
                uids = uids_tmp


        logging.debug("final UIDs: " + str(uids))

        return uids



    # fetch()
    #
    # fetch a specific message
    #
    # parameters:
    #  - self
    #  - uid (which is unique)
    # return:
    #  - headers, as dictionary - False if message does not exist
    #  - body
    #  - complete email message
    def fetch(self, uid):
        logging.debug("Fetching message %s" % str(uid))
        try:
            res, msg = self.connection.uid('fetch', uid, '(RFC822)')
        except imaplib.IMAP4.error as msg:
            logging.error(str(msg))
            sys.exit(1)

        if (res != 'OK'):
            logging.error("Something went wrong fetching email uid '%s'" % str(uid))
            return False, False, False

        try:
            raw_msg = msg[0][1].decode('utf-8')
        except UnicodeDecodeError:
            raw_msg = str(msg[0][1])
        email_msg = email.message_from_string(raw_msg)

        body = ''
        if (email_msg.is_multipart()):
            # message is multipart, extract all parts except images
            for mp in email_msg.walk():
                mp_type = mp.get_content_type()
                mp_cd = str(mp.get('Content-Disposition'))
                # skip plain attachments
                if (mp_type == 'text/plain' and 'attachment' not in mp_cd):
                    try:
                        body += mp.get_payload(decode = True).decode()
                    except UnicodeDecodeError:
                        body += str(mp.get_payload(decode = True))
        else:
            # message is not multipart, just extract it
            try:
                body = email_msg.get_payload(decode=True).decode()
            except UnicodeDecodeError:
                body = str(email_msg.get_payload(decode=True))

        header_parser = HeaderParser()
        headers = header_parser.parsestr(raw_msg)
        #print(headers.keys())

        return headers, body, email_msg



    # delete()
    #
    # delete a specific message
    #
    # parameters:
    #  - self
    #  - uid (which is unique)
    # return:
    #  - True/False
    def delete(self, uid):
        try:
            if (self.gmail is False):
                res = self.connection.uid('store', uid, '+FLAGS', '\\Deleted')
            else:
                res = self.connection.uid('store', uid, '+X-GM-LABELS', '\\Trash')
        except imaplib.IMAP4.error as msg:
            logging.error(str(msg))
            sys.exit(1)

        return True



# end IMAP class
#######################################################################









#######################################################################
# functions for the main program



# from: http://stackoverflow.com/questions/1094841/reusable-library-to-get-human-readable-version-of-file-size
# human_size()
#
# format number into human readable output
#
# parameters:
#  - number
# return:
#  - string with formatted number
def human_size(size_bytes):
    """
    format a size in bytes into a 'human' file size, e.g. bytes, KB, MB, GB, TB, PB
    Note that bytes/KB will be reported in whole numbers but MB and above will have greater precision
    e.g. 1 byte, 43 bytes, 443 KB, 4.3 MB, 4.43 GB, etc
    """
    if (size_bytes == 1):
        # because I really hate unnecessary plurals
        return "1 byte"

    suffixes_table = [('bytes',0),('KB',0),('MB',1),('GB',2),('TB',2), ('PB',2)]

    num = float(size_bytes)
    for suffix, precision in suffixes_table:
        if (num < 1024.0):
            break
        num /= 1024.0

    if (precision == 0):
        formatted_size = "%d" % num
    else:
        formatted_size = str(round(num, ndigits=precision))

    return "%s %s" % (formatted_size, suffix)



# account_action()
#
# handle everything for one account in the config
#
# parameter:
#  - config handle
#  - database handle
#  - account name
#  - account data
# return:
#  none
def account_action(config, database, account_name, account_data):
    # first extract account details
    try:
        imap_server = account_data['imap_server']
    except KeyError:
        logging.error("Account '%s' has no IMAP server specified" % account_name)

    try:
        username = account_data['username']
    except KeyError:
        logging.error("Account '%s' has no username specified" % account_name)

    try:
        password = account_data['password']
    except KeyError:
        logging.error("Account '%s' has no password specified" % account_name)

    ssl = True
    try:
        ssl = account_data['ssl']
    except KeyError:
        pass

    logging.debug("Credentials: %s @ %s" % (username, imap_server))


    try:
        conn = ImapConnection(config, account_name, imap_server, username, password, ssl)
    except:
        return
    if (conn is False):
        return


    # with the working connection, loop over all the rules
    try:
        rules = account_data['rules']
    except KeyError:
        logging.info("No rules defined for '%s'" % account_name)
        return
    if (rules is None or len(rules) == 0):
        logging.info("No rules defined for '%s'" % account_name)
        return

    logging.debug("%i rules for '%s'" % (len(rules), account_name))
    for rule in sorted(rules):
        logging.debug("Rule: %s" % rule)
        rule_data = rules[rule]
        rule_enabled = True
        try:
            t = rule_data['enabled']
            t = to_bool(t)
            if (t is False):
                rule_enabled = False
        except KeyError:
            pass
        except ValueError:
            logging.error("'enabled' must be a flag")
            sys.exit(1)
        if (rule_enabled is True):
            ret = process_rule(config, database, account_name, account_data, conn, rule, rule_data)
            if (ret is False):
                return

    logging.debug("Finished all rules for '%s'" % account_name)



# process_rule()
#
# process a single rule
#
# parmeter:
#  - config handle
#  - database handle
#  - account name
#  - account data
#  - IMAP connection handle
#  - rule name
#  - rule data
# return:
#  - True/False
def process_rule(config, database, account_name, account_data, conn, rule, rule_data):
    # four steps:
    # 1) find something
    # 2) process it
    # 3) remember it
    # 4) delete it

    # get rule data in order to find and process the emails in question
    try:
        filter = rule_data['filter']
    except KeyError:
        logging.info("Rule '%s' for '%s' has no filter defined" % (rule, account_name))
        return False

    try:
        action = rule_data['action']
    except KeyError:
        logging.info("Rule '%s' for '%s' has no action defined" % (rule, account_name))
        return False

    remember = False
    try:
        remember = rule_data['remember']
        remember = to_bool(remember)
    except KeyError:
        pass
    except ValueError:
        logging.error("'remember' for rule '%s' in account '%s' must be a boolean" % (rule, account_name))
        return False

    delete_after = False
    try:
        delete_after = rule_data['delete-after']
        delete_after = to_bool(delete_after)
    except KeyError:
        pass
    except ValueError:
        logging.error("'delete-after' for rule '%s' in account '%s' must be a boolean" % (rule, account_name))
        return False

    enabled = True
    try:
        enabled = rule_data['enabled']
        enabled = to_bool(enabled)
    except KeyError:
        pass
    except ValueError:
        logging.error("'enabled' for rule '%s' in account '%s' must be a boolean" % (rule, account_name))
        return False

    if (enabled is False):
        return True

    # the following filter methods are known:
    # * folder (required)
    # * from
    # * to
    # * cc
    # * list (not yet implemented)
    # * subject
    # * date (not yet implemented)
    # * body
    # the following additional search options are possible:
    # * AND: selects all messages which match both criteria
    # * OR: selects all messages which match either criteria
    # * AND NOT: selects all messages which match the first, but not the second criteria


    try:
        folder = filter['folder']
    except KeyError:
        logging.error("No folder specified for rule '%s' in account '%s'" % (rule, account_name))
        return False


    # select the folder
    if (conn.select_imap_folder(folder) is False):
        logging.error("Error selecting folder (%s) for rule '%s' in account '%s'" % (folder, rule, account_name))
        return False


    # Step 1: Find something
    res, uids = rule_search_messages(config, account_name, account_data, conn, rule, rule_data, filter)
    if (res is False):
        return False


    # Step 2: Process it
    logging.debug("%i email%s found for rule '%s' in account '%s'" % (len(uids), '' if len(uids) == 1 else 's', rule, account_name))
    for uid in uids:
        headers, body, message = conn.fetch(uid)
        if (headers is False):
            logging.error("Error fetching email '%s' for rule '%s' in account '%s'" % (str(uid), rule, account_name))
        # make sure that messages are not processed twice
        msg_id = str(headers['Message-Id']).replace('<', '').replace('>', '').replace(' ', '')
        if (database.msgid_seen_before(msg_id, account_name, rule) is False):
            logging.debug("Message-ID: " + msg_id)
            res = rule_process_message(config, account_name, rule, action, uid, conn, database, headers, body, message, msg_id)
            if (res is True):
                # Step 3: Remember it
                if (remember is True):
                    rule4 = rule_remember(database, account_name, rule, msg_id)
                else:
                    rule4 = True
                if (delete_after is True and rule4 is True):
                    # Step 4: Delete it
                    rule_delete(conn, account_name, rule, uid, msg_id)

    return True


# rule_delete()
#
# action rule: delete message
#
# parameter:
#  - IMAP connection
#  - account name
#  - rule name
#  - uid of message in IMAP folder
#  - message id
# return:
#  - True/False
# note:
#  - this function deletes the message after processing the rule
def rule_delete(conn, account_name, rule, uid, msg_id):
    logging.debug("Delete Message-ID: %s (UID: %s)" % (msg_id, str(uid)))
    res = conn.delete(uid)
    return True



# rule_remember()
#
# action rule: remember a message
#
# parameter:
#  - IMAP connection
#  - account name
#  - rule name
#  - uid of message in IMAP folder
#  - message id
# return:
#  - True/False
def rule_remember(database, account_name, rule, msg_id):
    logging.debug("Remember Message-ID: %s" % msg_id)
    database.remember_msg_id(msg_id, account_name, rule)
    return True



# rule_process_message()
#
# action rule: process a message based on defined action
#
# parameter:
#  - config handle
#  - account name
#  - rule name
#  - action name
#  - uid of message in IMAP folder
#  - IMAP connection
#  - database connection
#  - message headers
#  - message body
#  - whole message
#  - message id
# return:
#  - True/False
def rule_process_message(config, account_name, rule, action, uid, conn, database, headers, body, message, msg_id):
    # first need the action type
    try:
        action_type = action['action-type']
    except KeyError:
        logging.error("Rule '%s' for '%s' has no action type defined" % (rule, account_name))
        return False

    if (action_type == 'test'):
        logging.debug("pass (debug)")
        return True
    elif (action_type == 'majordomo'):
        return rule_process_majordomo(config, account_name, rule, action, uid, conn, database, headers, body, message, msg_id)
    elif (action_type == 'mailman2'):
        return rule_process_mailman2(config, account_name, rule, action, uid, conn, database, headers, body, message, msg_id)
    elif (action_type == 'pglister'):
        return rule_process_pglister(config, account_name, rule, action, uid, conn, database, headers, body, message, msg_id)
    elif (action_type == 'delete'):
        return rule_process_delete(config, account_name, rule, action, uid, conn, database, headers, body, message, msg_id)
    elif (action_type == 'forward'):
        return rule_process_forward(config, account_name, rule, action, uid, conn, database, headers, body, message, msg_id)
    elif (action_type == 'retweet'):
        return rule_process_retweet(config, account_name, rule, action, uid, conn, database, headers, body, message, msg_id)
    else:
        logging.error("Unknown action type '%s' in rule '%s' for '%s'" % (action_type, rule, account_name))
        return False

    return False



# rule_process_retweet()
#
# action rule: retweet a message which is in the current mail
#
# parameter:
#  - config handle
#  - account name
#  - rule name
#  - action name
#  - uid of message in IMAP folder
#  - IMAP connection
#  - database connection
#  - message headers
#  - message body
#  - whole message
#  - message id
# return:
#  - True/False
# note:
#  - this function handles the "retweet" action
def rule_process_retweet(config, account_name, rule, action, uid, conn, database, headers, body, message, msg_id):
    # retweet rule needs the Twitter account from the rule data
    try:
        twitter_account = action['twitter-account']
    except KeyError:
        logging.error("Rule '%s' for '%s' has no twitter account defined" % (rule, account_name))
        return False
    # maximum number of tweets per run
    try:
        max_tweets = action['max-tweets']
    except KeyError:
        logging.error("Rule '%s' for '%s' has no maximum tweet number defined" % (rule, account_name))
        return False
    try:
        max_tweets = int(max_tweets)
        if (max_tweets > 100 or max_tweets < 1):
            raise ValueError
    except ValueError:
        logging.error("Rule '%s' for '%s' has no maximum tweet number defined" % (rule, account_name))
        return False
    # random factor for tweeting only once in a while
    try:
        random_factor = action['random-factor']
    except KeyError:
        logging.error("Rule '%s' for '%s' has no random factor defined" % (rule, account_name))
        return False
    try:
        random_factor = float(random_factor)
        if (random_factor > 1 or random_factor < 0):
            raise ValueError
    except ValueError:
        logging.error("Rule '%s' for '%s' has no random factor defined" % (rule, account_name))
        return False

    # check how many retweets are already done for this run
    number_retweets = config.get_retweets(twitter_account)
    if (number_retweets >= max_tweets):
        logging.debug("Enough Retweets for this run")
        # don't delete the email
        return False

    # add randomness
    random.seed(os.urandom(20))
    rand_number = random.uniform(0, 1)
    if (rand_number >= random_factor):
        logging.debug("Skip Tweets in this run")
        config.set_retweets(twitter_account, 10000000)
        # don't delete the email
        return False
    logging.debug("Passed random factor for Tweets")


    # it also needs Twitter credentials
    try:
        twitter_consumer_key = config.configfile['twitter'][twitter_account]['consumer-key']
    except KeyError:
        logging.error("Account '%s' has no Twitter account defined for forward rule '%s'" % (account_name, rule))
        return False
    try:
        twitter_consumer_secret = config.configfile['twitter'][twitter_account]['consumer-secret']
    except KeyError:
        logging.error("Account '%s' has no Twitter account defined for forward rule '%s'" % (account_name, rule))
        return False
    try:
        twitter_access_token_key = config.configfile['twitter'][twitter_account]['access-token-key']
    except KeyError:
        logging.error("Account '%s' has no Twitter account defined for forward rule '%s'" % (account_name, rule))
        return False
    try:
        twitter_access_token_secret = config.configfile['twitter'][twitter_account]['access-token-secret']
    except KeyError:
        logging.error("Account '%s' has no Twitter account defined for forward rule '%s'" % (account_name, rule))
        return False


    parser = MyMessageParser()
    links = parser.parse_message(message)
    links = resolve_links(links)
    links = list(dict.fromkeys(links))
    #print("\n\n".join(links))
    if (links is False):
        # something went wrong during message link resolve
        logging.debug("No links found in Message")
        return False
    status_links = extract_twitter_status_links(links)

    # no links found, do nothing with this message
    if (len(status_links) == 0):
        logging.debug("No links found in Message")
        return False


    # connect to Twitter
    twitter_api = TW.Api(consumer_key = twitter_consumer_key,
                         consumer_secret = twitter_consumer_secret,
                         access_token_key = twitter_access_token_key,
                         access_token_secret = twitter_access_token_secret)

    number_retweets = 0
    return_now = False
    for t in (status_links):
        t_split = t.split('/')
        retweeted = False
        try:
            rs = twitter_api.PostRetweet(t_split[-1])
            logging.debug("Retweeted: %s" % (str(t_split[-1])))
            retweeted = True
        except (TW.TwitterError) as err:
            if (str(err.message[0]['code']) == "327"):
                logging.debug("Already retweeted: %s" % (str(t_split[-1])))
                retweeted = True
                return_now = True
            elif (str(err.message[0]['code']) == "144"):
                logging.debug("Tweet deleted: %s" % (str(t_split[-1])))
                retweeted = True
                return_now = True
            else:
                logging.error("Unknown Twitter error: (%s) %s" % (str(err.message[0]['code']), err.message[0]['message']))

        if (retweeted is True):
            config.add_retweet(twitter_account)
            number_retweets = config.get_retweets(twitter_account)
            if (return_now is True):
                # the Tweet is deleted, remove mail
                return True
            if (number_retweets >= max_tweets):
                logging.debug("Enough Retweets")
                return True

    return False



# rule_process_forward()
#
# action rule: forward a message
#
# parameter:
#  - config handle
#  - account name
#  - rule name
#  - action name
#  - uid of message in IMAP folder
#  - IMAP connection
#  - database connection
#  - message headers
#  - message body
#  - whole message
#  - message id
# return:
#  - True/False
# note:
#  - this function handles the "forward" action
def rule_process_forward(config, account_name, rule, action, uid, conn, database, headers, body, message, msg_id):
    # forward rule needs the recipient from the rule data
    try:
        recipient = action['recipient']
    except KeyError:
        logging.error("Rule '%s' for '%s' has no recipient defined" % (rule, account_name))
        return False

    # it also needs SMTP credentials
    try:
        smtp_server = config.configfile['accounts'][account_name]['smtp_server']
    except KeyError:
        logging.error("Account '%s' has no SMTP server defined for forward rule '%s'" % (account_name, rule))
        return False
    try:
        smtp_port = config.configfile['accounts'][account_name]['smtp_port']
    except KeyError:
        logging.error("Account '%s' has no SMTP port defined for forward rule '%s'" % (account_name, rule))
        return False
    try:
        username = config.configfile['accounts'][account_name]['username']
    except KeyError:
        # this one should exist
        logging.error("Account '%s' has no username defined for forward rule '%s'" % (account_name, rule))
        return False
    try:
        password = config.configfile['accounts'][account_name]['password']
    except KeyError:
        # this one should exist too
        logging.error("Account '%s' has no password defined for forward rule '%s'" % (account_name, rule))
        return False



    ##print(message)
    #message.replace_header("Message-ID", '')
    #print(message.as_string())
    #print()
    #print()
    #print(message['From'])

    # Google might rewrite the From header, if the email address is not known to the account
    addr = email.utils.parseaddr(message['From'])
    #print(addr[1])

    smtp = smtplib.SMTP_SSL(smtp_server, smtp_port)
    smtp.login(username, password)
    smtp.sendmail(addr[1], recipient, message.as_string())
    smtp.quit()

    logging.debug("Forward Message-ID: %s (UID: %s) to %s" % (msg_id, str(uid), str(recipient)))
    return True



# rule_process_delete()
#
# action rule: delete a message
#
# parameter:
#  - config handle
#  - account name
#  - rule name
#  - action name
#  - uid of message in IMAP folder
#  - IMAP connection
#  - database connection
#  - message headers
#  - message body
#  - whole message
#  - message id
# return:
#  - True/False
# note:
#  - this function handles the "delete" action
def rule_process_delete(config, account_name, rule, action, uid, conn, database, headers, body, message, msg_id):
    logging.debug("Delete Message-ID: %s (UID: %s)" % (msg_id, str(uid)))
    res = conn.delete(uid)
    return True



# rule_process_pglister()
#
# action rule: process a PGListener admin email
#
# parameter:
#  - config handle
#  - account name
#  - rule name
#  - action name
#  - uid of message in IMAP folder
#  - IMAP connection
#  - database connection
#  - message headers
#  - message body
#  - whole message
#  - message id
# return:
#  - True/False
def rule_process_pglister(config, account_name, rule, action, uid, conn, database, headers, body, message, msg_id):
    # PGLister rule needs the pglister-action
    try:
        pglister_action = action['pglister-action']
    except KeyError:
        logging.error("Rule '%s' for '%s' has no PGLister action defined" % (rule, account_name))
        return False
    # the 'cleanup' action is special, as in not supported by the website
    if (pglister_action not in ['approve', 'whitelist', 'discard', 'reject', 'cleanup']):
        logging.error("Unknown PGLister action '%s' in rule '%s' for '%s'" % (pglister_action, rule, account_name))
        return False

    # additionally, either pglister-subject or pglister-from must be set, in order to identify emails in pglister
    if (pglister_action != 'cleanup'):
        try:
            pglister_subject = action['pglister-subject']
        except KeyError:
            pglister_subject = ''

        try:
            pglister_from = action['pglister-from']
        except KeyError:
            pglister_from = ''

        if (len(pglister_subject) == 0 and len(pglister_from) == 0):
            logging.error("Either 'pglister-subject' or 'pglister-from' must be set, in rule '%s' for '%s'" % (rule, account_name))
            return False
    else:
        pglister_subject = ''
        pglister_from = ''

    body = body.encode().decode('unicode_escape')
    #logging.debug(body)

    lines = body.splitlines()
    mail_sender = None
    mail_subject = None
    mail_token = None
    for line in lines:
        find_sender = re.search('^Sender:[\s\t]+(.+)', line)
        if (find_sender):
            mail_sender = str(find_sender.group(1))

        find_subject = re.search('^Subject:[\s\t]+(.+)', line)
        if (find_subject):
            mail_subject = str(find_subject.group(1))

        find_token = re.search('^Preview:.+moderate\/([a-z0-9]+)\/', line)
        if (find_token):
            mail_token = str(find_token.group(1))

    if (mail_sender is None and mail_subject is None):
        # these must exist even for the cleanup task
        logging.error("Couldn't find sender and subject in email for rule '%s' for '%s'" % (rule, account_name))
        return False

    if (mail_token is None):
        # this must exist even for the cleanup task
        logging.error("Couldn't find moderation token in email for rule '%s' for '%s'" % (rule, account_name))
        return False

    if (mail_sender is None):
        mail_sender = ''
    if (mail_subject is None):
        mail_subject = ''

    session = requests.session()

    # first check if the token was already handled
    # could be an earlier request, or someone else moderated the email
    preview_link = 'https://lists.postgresql.org/moderate/' + mail_token + '/preview/'
    preview_form = get_url(preview_link, session, ignore_404 = True)
    token_handled = re.search('Token does not exist', preview_form, re.DOTALL)

    if (token_handled and pglister_action == 'cleanup'):
        # token is already handled, silently delete the email
        rule_delete(conn, account_name, rule, uid, msg_id)
        return True


    if (token_handled):
        logging.debug("Token already handled, nothing to do")
        return True


    # we got all the information we need about this email
    # now compare subject and from to the rules
    # an email can only be handled if either "from" or "subject" is specified - this avoids handling all emails by mistake
    pglister_handle_email_subject = False
    pglister_handle_email_from = False
    if (len(pglister_subject) > 0):
        # compare subject
        if (mail_subject.lower().find(pglister_subject.lower()) > -1):
            pglister_handle_email_subject = True
    if (len(pglister_from) > 0):
        # compare from
        if (mail_sender.lower().find(pglister_from.lower()) > -1):
            pglister_handle_email_from = True

    pglister_handle_email = False
    if (len(pglister_subject) > 0 and len(pglister_from) > 0):
        # if both arguments are given, both must be found
        if (pglister_handle_email_subject is True and pglister_handle_email_from is True):
            pglister_handle_email = True
    elif (len(pglister_subject) > 0):
        if (pglister_handle_email_subject is True):
            pglister_handle_email = True
    elif (len(pglister_from) > 0):
        if (pglister_handle_email_from is True):
            pglister_handle_email = True


    if (pglister_handle_email is True):
        mm_link_form_data_changed = True
        # this email was flagged, handle it according to the rule set
        submit_link = 'https://lists.postgresql.org/moderate/' + mail_token + '/' + pglister_action + '/'
        logging.info("%s PGLister email %s" % (pglister_action, str(mail_token)))
        get_url(submit_link, session, ignore_404 = True)


    return False



# rule_process_majordomo()
#
# action rule: process a Majordomo admin email
#
# parameter:
#  - config handle
#  - account name
#  - rule name
#  - action name
#  - uid of message in IMAP folder
#  - IMAP connection
#  - database connection
#  - message headers
#  - message body
#  - whole message
#  - message id
# return:
#  - True/False
def rule_process_majordomo(config, account_name, rule, action, uid, conn, database, headers, body, message, msg_id):
    # majordomo rule needs the action-url and the majordomo-action
    try:
        action_url = action['action-url']
    except KeyError:
        logging.error("Rule '%s' for '%s' has no action url defined" % (rule, account_name))
        return False

    try:
        majordomo_action = action['majordomo-action']
    except KeyError:
        logging.error("Rule '%s' for '%s' has no majordomo action defined" % (rule, account_name))
        return False
    if (majordomo_action not in ['accept', 'accept-archive', 'accept-hide', 'reject', 'reject-quiet']):
        logging.error("Unknown majordomo action '%s' in rule '%s' for '%s'" % (majordomo_action, rule, account_name))
        return False

    # find link in email
    md_link = re.search('(' + re.escape(action_url) + '[^\>\<\"\']+)', body, re.DOTALL)
    if (md_link):
        md_link = str(md_link.group(1))
        logging.debug("Found majordomo URL: " + md_link)
    else:
        logging.error("Couldn't find majordomo url matching '%s' in email for rule '%s' for '%s'" % (action_url, rule, account_name))
        return False

    session = requests.session()
    md_form = get_url(md_link, session)

    # first check if the token was already handled
    # could be an earlier request, or someone else
    md_handled = re.search('The request may have been accepted or rejected by another person', md_form, re.DOTALL)
    if (md_handled):
        logging.debug("Token already handled, nothing to do")
        return True


    md_form_data = extract_form_data(md_form, md_link)

    # add majordomo action
    md_form_data['fields']['a'] = majordomo_action
    res = get_url(md_form_data['action'], session, md_form_data['fields'])
    logging.info("Rejected majordomo email based on rule '%s' for '%s'" % (rule, account_name))

    return True




# rule_process_mailman2()
#
# action rule: process a Mailman 2 admin email
#
# parameter:
#  - config handle
#  - account name
#  - rule name
#  - action name
#  - uid of message in IMAP folder
#  - IMAP connection
#  - database connection
#  - message headers
#  - message body
#  - whole message
#  - message id
# return:
#  - True/False
def rule_process_mailman2(config, account_name, rule, action, uid, conn, database, headers, body, message, msg_id):
    # Mailman rule needs the mailman-password and the mailman-action
    try:
        mailman_password = action['mailman-password']
    except KeyError:
        logging.error("Rule '%s' for '%s' has no Mailman password defined" % (rule, account_name))
        return False

    try:
        mailman_action = action['mailman-action']
    except KeyError:
        logging.error("Rule '%s' for '%s' has no Mailman action defined" % (rule, account_name))
        return False
    if (mailman_action not in ['defer', 'approve', 'reject', 'discard']):
        logging.error("Unknown Mailman action '%s' in rule '%s' for '%s'" % (mailman_action, rule, account_name))
        return False

    # additionally, either mailman-subject or mailman-from must be set, in order to identify emails in Mailman
    try:
        mailman_subject = action['mailman-subject']
    except KeyError:
        mailman_subject = ''

    try:
        mailman_from = action['mailman-from']
    except KeyError:
        mailman_from = ''

    if (len(mailman_subject) == 0 and len(mailman_from) == 0):
        logging.error("Either 'mailman-subject' or 'mailman-from' must be set, in rule '%s' for '%s'" % (rule, account_name))
        return False


    # find link in email
    body = body.encode().decode('unicode_escape')
    #logging.debug(body)
    mm_link = re.search('consideration at:[\r\n\s\t]+(http[^\r\n\s\t]+)', body, re.DOTALL)
    if (mm_link):
        mm_link = str(mm_link.group(1))
        logging.debug("Found Mailman URL: " + mm_link)
    else:
        mm_link = re.search('At your convenience, visit:[\r\n\s\t]+(http[^\r\n\s\t]+)', body, re.DOTALL)
        if (mm_link):
            mm_link = str(mm_link.group(1))
            logging.debug("Found Mailman URL: " + mm_link)
        else:
            mm_link = re.search('Bitte besuchen Sie bei Gelegenheit[\r\n\s\t]+(http[^\r\n\s\t]+)', body, re.DOTALL)
            if (mm_link):
                mm_link = str(mm_link.group(1))
                logging.debug("Found Mailman URL: " + mm_link)
            else:
                logging.error("Couldn't find Mailman url in email for rule '%s' for '%s'" % (rule, account_name))
                return False

    session = requests.session()
    #logging.debug(mm_link)
    #sys.exit(0)
    mm_login_form = get_url(mm_link, session)


    # Mailman has a funny understanding of valid html
    # discussion:
    # the html which is generated by Mailman is not well formed, and contains multiple errors
    # that's fine for modern browsers, but libraries like "xml.etree.ElementTree" don't like it
    # either all the invalid html must be fixed, or manual parsing is more feasible

    # action tag spawns over multiple lines
    mm_login_extract = re.search('^(.+<FORM METHOD=)"?POST"?.+?(ACTION=.+)$', mm_login_form, re.DOTALL)
    if (mm_login_extract):
        mm_login_form = str(mm_login_extract.group(1)) + '"POST" ' + str(mm_login_extract.group(2))
    else:
        logging.error("Did Mailman finally fix the invalid HTML?")
        return False

    # input tags spawns over multiple lines
    mm_login_extract = re.search('^(.+<INPUT type="SUBMIT").+?(name=".+?").+?(value=".+?")(.+)$', mm_login_form, re.DOTALL)
    if (mm_login_extract):
        mm_login_form = str(mm_login_extract.group(1)) + " " + str(mm_login_extract.group(2)) + " " + str(mm_login_extract.group(3)) + " " + str(mm_login_extract.group(4))
    else:
        logging.error("Did Mailman finally fix the invalid HTML?")
        return False


    mm_login_form_data = extract_form_data(mm_login_form, mm_link)
    #logging.debug(mm_login_form)
    #logging.debug(mm_login_form_data)


    # login into website
    mm_login_form_data['fields']['adminpw'] = mailman_password
    mm_list_form = get_url(mm_login_form_data['action'], session, mm_login_form_data['fields'])


    # see if there are pending requests
    mm_handled = re.search('There are no pending requests', mm_list_form, re.DOTALL)
    if (mm_handled):
        logging.debug("Message already handled, nothing to do")
        return True
    #logging.debug(mm_list_form)


    # see if login was possible
    mm_handled1 = re.search('This page contains a summary of the current', mm_list_form, re.DOTALL)
    mm_handled2 = re.search('Diese Seite zeigt ein', mm_list_form, re.DOTALL)
    if (not mm_handled1 and not mm_handled2):
        logging.error("Could not login to Mailman")
        return False
    #logging.debug(mm_list_form)


    # extract all 'view all' links from the form
    # basically handle the open tickets one by one (or: all from one email address together)
    links = re.findall('<a[^>]+?>view all messages from.+?<\/a>', mm_list_form, re.DOTALL)

    for link in links:
        mm_link = re.search('href="(.+?)"', link, re.DOTALL|re.IGNORECASE)
        if (not mm_link):
            logging.error("Could not extract link: %s" % link)
            return False

        mm_link = str(mm_link.group(1))
        #logging.debug("Link: %s" % mm_link)
        mm_link_form = get_url(mm_link, session)
        #logging.debug(mm_link_form)

        # from here, we don't need the content of the textarea fields - and they make parsing the HTML quite complicated
        mm_link_form = re.sub(r'<td><TEXTAREA NAME=(comment[^ ]+).+?</TEXTAREA></td>', r'<td><textarea name="\1"></textarea></td>', mm_link_form, flags=re.DOTALL)
        mm_link_form = re.sub(r'<td><TEXTAREA NAME=(headers[^ ]+).+?</TEXTAREA></td>', r'<td><textarea name="\1"></textarea></td>', mm_link_form, flags=re.DOTALL)
        mm_link_form = re.sub(r'<td><TEXTAREA NAME=(fulltext[^ ]+).+?</TEXTAREA></td>', r'<td><textarea name="\1"></textarea></td>', mm_link_form, flags=re.DOTALL)
        # the HTML has multiple input tags in the same line
        mm_link_form = re.sub(r'(Additionally, forward this message to: )', r'\1\n', mm_link_form, flags=re.DOTALL)
        #logging.debug(mm_link_form)


        # first extract all form data
        mm_link_form_data = extract_form_data(mm_link_form, mm_link)
        mm_link_form_data_changed = False
        #logging.debug(mm_link_form_data)

        # now split it up by the separate tables ect for each email to approve
        mm_all_emails = re.findall('<center><h2>Posting Held.*?<\/h2><\/center>.+?<table.+?<table.*?<\/table.*?<\/table>', mm_link_form, re.DOTALL)
        #logging.debug(mm_one_email)


        # loop over every email in the list
        for mm_one_email in mm_all_emails:

            # the only radio field in the table also happens to contain the ID of the email message
            mm_id = re.search('<INPUT name="([\d]+)" type="RADIO" value="0" CHECKED >', mm_one_email, flags=re.DOTALL)
            if (mm_id):
                mm_id = mm_id.group(1)
                logging.debug("Mailman email ID: %s" % mm_id)
            else:
                logging.error("Parse error, no Mailman email ID found!")
                # if parsing this part failed, it's likely that the remaining parts will fail as well - abort
                return False

            # extract additional data for the email
            mm_from = re.search('<td ALIGN="right"><strong>From:</strong></td>.+?<td>(.*?)</td>', mm_one_email, flags=re.DOTALL)
            if (mm_from):
                mm_from = handle_unicode(mm_from.group(1))
            else:
                logging.error("No From address found in Mailman form for: %s" % mm_id)
                return False

            # Subject can be empty
            mm_subject = re.search('<td ALIGN="right"><strong>Subject:</strong></td>.*?<td>(.*?)</td>', mm_one_email, flags=re.DOTALL)
            if (mm_subject):
                mm_subject = handle_unicode(mm_subject.group(1))
            else:
                logging.error("No Subject found in Mailman form for: %s" % mm_id)
                return False


            # we got all the information we need about this email
            # now compare subject and from to the rules
            # an email can only be handled if either "from" or "subject" is specified - this avoids handling all emails by mistake
            mm_handle_email_subject = False
            mm_handle_email_from = False
            if (len(mailman_subject) > 0):
                # compare subject
                if (mm_subject.lower().find(mailman_subject.lower()) > -1):
                    mm_handle_email_subject = True
            if (len(mailman_from) > 0):
                # compare from
                if (mm_from.lower().find(mailman_from.lower()) > -1):
                    mm_handle_email_from = True

            mm_handle_email = False
            if (len(mailman_subject) > 0 and len(mailman_from) > 0):
                # if both arguments are given, both must be found
                if (mm_handle_email_subject is True and mm_handle_email_from is True):
                    mm_handle_email = True
            elif (len(mailman_subject) > 0):
                if (mm_handle_email_subject is True):
                    mm_handle_email = True
            elif (len(mailman_from) > 0):
                if (mm_handle_email_from is True):
                    mm_handle_email = True


            if (mm_handle_email is True):
                mm_link_form_data_changed = True
                # this email was flagged, handle it according to the rule set
                # field name in the form is the ID
                # value is:
                #  0: Defer
                #  1: Approve
                #  2: Reject
                #  3: Discard
                if (mailman_action == 'defer'):
                    mm_link_form_data['fields'][mm_id] = '0'
                    logging.info("defer Mailman email %s" % str(mm_id))
                elif (mailman_action == 'approve'):
                    mm_link_form_data['fields'][mm_id] = '1'
                    logging.info("approve Mailman email %s" % str(mm_id))
                elif (mailman_action == 'reject'):
                    mm_link_form_data['fields'][mm_id] = '2'
                    logging.info("reject Mailman email %s" % str(mm_id))
                elif (mailman_action == 'discard'):
                    mm_link_form_data['fields'][mm_id] = '3'
                    logging.info("discard Mailman email %s" % str(mm_id))


        if (mm_link_form_data_changed is True):
            logging.debug("Form data changed, need to submit form")
            #logging.debug(mm_link_form_data)
            # before sending the form back, de-select all 'preserve-*' and 'forward-*' fields (checkboxes), and 'forward-addr-*' (forward address field)
            for t in mm_link_form_data['fields']:
                if (t[0:9] == 'preserve-' or t[0:8] == 'forward-' or t[0:13] == 'forward-addr-'):
                    mm_link_form_data['fields'][t] = ''
            #logging.debug(mm_link_form_data)
            # verify that no checkboxes remain which are checked (because extract_form_data() returns them checked with the value)
            for t in mm_link_form_data['fields']:
                if (mm_link_form_data['fields'][t] == 'on'):
                    logging.error("Field '%s' is still set to on, please verify form!" % t)
                    return False
            res = get_url(mm_link_form_data['action'], session, mm_link_form_data['fields'])
        #else:
        #    logging.debug("Form unchanged")
        #    logging.debug(mm_link_form_data)

        #print(mm_link_form_data)


    return True



# rule_search_messages()
#
# action rule: process a Mailman 2 admin email
#
# parameter:
#  - config handle
#  - account name
#  - account data
#  - IMAP connection
#  - rule name
#  - rule data
#  - filter data
# return:
#  - True/False
#  - dict with UIDs
def rule_search_messages(config, account_name, account_data, conn, rule, rule_data, filter):

    # get all search criteria from config
    try:
        search_from = filter['from']
    except KeyError:
        search_from = ''

    try:
        search_to = filter['to']
    except KeyError:
        search_to = ''

    try:
        search_cc = filter['cc']
    except KeyError:
        search_cc = ''

    try:
        search_list = filter['list']
    except KeyError:
        search_list = ''

    try:
        search_subject = filter['subject']
    except KeyError:
        search_subject = ''

    try:
        search_date = filter['date']
    except KeyError:
        search_date = ''

    try:
        search_body = filter['body']
    except KeyError:
        search_body = ''


    # https://www.example-code.com/python/imap_search.asp
    # https://tools.ietf.org/html/rfc3501#section-6.4.4
    # https://www.chilkatsoft.com/p/p_379.asp


    uids = []
    no_results = False
    if (len(search_from) > 0 and no_results is False):
        uids = conn.search('FROM', search_from, uids)
        if (len(uids) == 0):
            no_results = True

    if (len(search_to) > 0 and no_results is False):
        uids = conn.search('TO', search_to, uids)
        if (len(uids) == 0):
            no_results = True

    if (len(search_cc) > 0 and no_results is False):
        uids = conn.search('CC', search_cc, uids)
        if (len(uids) == 0):
            no_results = True

    if (len(search_subject) > 0 and no_results is False):
        uids = conn.search('SUBJECT', search_subject, uids)
        if (len(uids) == 0):
            no_results = True

    if (len(search_body) > 0 and no_results is False):
        uids = conn.search('BODY', search_body, uids)
        if (len(uids) == 0):
            no_results = True


    if (len(uids) == 0):
        logging.debug("Filter for rule '%s' in account '%s' came up empty" % (rule, account_name))
        return True, uids

    return True, uids



# resolve_forward_link()
#
# resolve a link to the final destination
#
# parameter:
#  - link
# return:
#  - resolved link, or False
def resolve_forward_link(link):

    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests.packages.urllib3").setLevel(logging.WARNING)
    logging.getLogger("httplib").setLevel(logging.WARNING)
    # set language to 'German', all content will be rendered in German and all functionality is available
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1',
               'Accept-Encoding': 'gzip, deflate',
               'Accept-Language' : 'de'}

    session = requests.session()

    # GET request
    rs = session.request('GET', link, headers = headers, allow_redirects=False)
    if (rs.status_code == 301 or rs.status_code == 302):
        return rs.headers['Location']

    # this is supposed to be a forward link
    # if it can't be resolved, something is wrong
    return False



# resolve_links()
#
# resolve certain links to their final destination
#
# parameter:
#  - list with links
# return:
#  - list with updated links
def resolve_links(links):
    ret = []

    for l in links:
        if (l == 'https://links.ifttt.com/wf/c='):
            continue
        if (l == 'https://links.ifttt.com/wf/click?upn='):
            continue
        if (l.startswith('https://links.ifttt.com/wf/click?') and len(l) < 100):
            continue
        if (l.startswith('https://links.ifttt.com/wf/click?')):
            l2 = resolve_forward_link(l)
            if (l2 is False):
                logging.error("Can't resolve link: %s" % (l))
                return False
            ret.append(l2)
        else:
            ret.append(l)

    return ret



# extract_twitter_status_links()
#
# extract the status ID from a Twitter link
#
# parameter:
#  - Twitter link
# return:
#  - status ID
def extract_twitter_status_links(links):
    ret = []

    for l in links:
        if ("http://twitter.com" in l or "https://twitter.com" in l):
            if ("/status/" in l):
                ret.append(l)

    return ret



# handle_unicode()
#
# handle UTF-8 conversation for strings
#
# parameter:
#  - string
# return:
#  string
def handle_unicode(in_str):

    try:
        ret_str = str(in_str.decode())
    except UnicodeDecodeError:
        ret_str = str(in_str)
    except AttributeError:
        ret_str = str(in_str)

    return ret_str



# to_bool()
#
# make a string a boolean
#
# parameter:
#  - string
# return:
#  - boolean
def to_bool(in_str):
    #logging.debug("Type: " + str(type(in_str)))
    if (isinstance(in_str, str) and in_str):
        if (in_str.lower() in ['true', 't', '1']):
            return True
        elif (in_str.lower() in ['false', 'f', '0']):
            return False
    elif (isinstance(in_str, int) and in_str):
        if (in_str == 1):
            return True
        elif (in_str == 0):
            return False
    elif (isinstance(in_str, bool)):
        # that's alright
        return in_str

    raise ValueError("not a boolean value: %s" % in_str)



# get_url()
#
# GET a specific url, handle compression
#
# parameter:
#  - url
#  - requests object
#  - data (optional, dictionary)
#  - ignore_404 (optional, boolean)
# return:
#  - content of the link
def get_url(url, session, data = None, ignore_404 = False):

    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests.packages.urllib3").setLevel(logging.WARNING)
    logging.getLogger("httplib").setLevel(logging.WARNING)
    # set language to 'German', all content will be rendered in German and all functionality is available
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1',
               'Accept-Encoding': 'gzip, deflate',
               'Accept-Language' : 'de'}

    if (data is None):
        # GET request
        rs = session.request('GET', url, headers = headers)
    else:
        # POST request
        rs = session.request('POST', url, data = data, headers = headers)


    #print(rs.headers)

    if (rs.status_code != 200):
        if (rs.status_code == 400):
            logging.error("HTTPError = 400 (Bad Request)")
        elif (rs.status_code == 401):
            logging.error("HTTPError = 401 (Unauthorized)")
        elif (rs.status_code == 403):
            logging.error("HTTPError = 403 (Forbidden)")
        elif (rs.status_code == 404):
            if (ignore_404 is False):
                logging.error("HTTPError = 404 (URL not found)")
        elif (rs.status_code == 408):
            logging.error("HTTPError = 408 (Request Timeout)")
        elif (rs.status_code == 418):
            logging.error("HTTPError = 418 (I'm a teapot)")
        elif (rs.status_code == 500):
            logging.error("HTTPError = 500 (Internal Server Error)")
        elif (rs.status_code == 502):
            logging.error("HTTPError = 502 (Bad Gateway)")
        elif (rs.status_code == 503):
            logging.error("HTTPError = 503 (Service Unavailable)")
        elif (rs.status_code == 504):
            logging.error("HTTPError = 504 (Gateway Timeout)")
        else:
            logging.error("HTTPError = " + str(rs.status_code) + "")
        if (rs.status_code == 404 and ignore_404 is True):
            pass
        else:
            sys.exit(1)

    if (len(rs.text) == 0):
        logging.error("failed to download the url")
        sys.exit(1)

    data = rs.text

    logging.debug("fetched " + human_size(len(data)))

    return data



# extract_form_data()
#
# extract fields from a HTML form
#
# parameter:
#  - content of the HTML form
#  - base URL for the website
# return:
#  - dictionary with 'action' as new URL, and 'fields'
def extract_form_data(form_content, base_url):
    data = {}
    data['action'] = None
    data['fields'] = {}


    # first extract the target for the form
    form_action = re.search('<form.+?action="(.+?)".*?>(.*)<\/form>', form_content, re.DOTALL|re.IGNORECASE)
    if (form_action):
        # and normalize it
        data['action'] = urljoin(base_url, str(form_action.group(1)))
        form3_inner_content = str(form_action.group(2))
        # there might be a "name" tag hidden
        form_name = re.search('<form[^>]+name="(.+?)"', form_content, re.DOTALL|re.IGNORECASE)
        if (form_name):
            #logging.debug("found     name: " + str(form_name.group(1)) + " = '" + str(form_action.group(1)) + "'")
            data['fields'][str(form_name.group(1))] = str(form_action.group(1))
    else:
        # not finding a target is a problem
        logging.error("Can't extract action field from form!")
        sys.exit(1)


    # go through the form, line by line
    for line in form3_inner_content.splitlines(True):
        #print("line: " + line)

        line_input = re.search('<input(.+?>)', line, re.DOTALL|re.IGNORECASE)
        if (line_input):
            input_elem = {}
            line_input = line_input.group(1)
            # search for the different elements which might appear in an <input /> element
            for elem in ['name', 'type', 'value']:
                line_elem = re.search(' ' + elem + '[\s\t]*=[\s\t]*"(.*?)"', line_input, re.DOTALL|re.IGNORECASE)
                if (line_elem):
                    input_elem[elem] = handle_unicode(line_elem.group(1))
                else:
                    # if you place a tag in the HTML code which is not using "" and then place a '/' in your value, you are just ...
                    line_elem = re.search(' ' + elem + '[\s\t]*=([^\s\t]*)[\s\t\/>]', line_input, re.DOTALL|re.IGNORECASE)
                    if (line_elem):
                        input_elem[elem] = handle_unicode(line_elem.group(1))

            # check if we have everything
            try:
                t = input_elem['name']
            except KeyError:
                break
            try:
                t = input_elem['type']
            except KeyError:
                break
            input_elem['type'] = input_elem['type'].lower()
            try:
                t = input_elem['value']
            except KeyError:
                # this one might be missed, fill in default
                input_elem['value'] = ''

            # "radio" element might have a "checked" element
            if (input_elem['type'] == 'radio'):
                line_radio_checked = False
                line_radio = re.search(' checked[\s\t]*=[\s\t]*"?checked"?', line_input, re.DOTALL|re.IGNORECASE)
                if (line_radio):
                    line_radio_checked = True
                else:
                    # that might catch the wrong text, but unfortunately some people write crappy HTML
                    line_radio = re.search(' checked[\s\t\/>]', line_input, re.DOTALL|re.IGNORECASE)
                    if (line_radio):
                        line_radio_checked = True
                if (line_radio_checked is True):
                    # the current element is checked, overwrite any existing data
                    #logging.debug("found {:>10}: {:s} = {:s}".format(input_elem['type'], input_elem['name'], input_elem['value']))
                    data['fields'][input_elem['name']] = input_elem['value']
                else:
                    # the current element is not checked, only store if nothing previously stored (first element will be checked)
                    try:
                        t = data['fields'][input_elem['name']]
                    except KeyError:
                        logging.debug("found {:>10}: {:s} = {:s}".format(input_elem['type'], input_elem['name'], input_elem['value']))
                        data['fields'][input_elem['name']] = input_elem['value']


            else:
                # no radio button, just store the value
                #logging.debug("found {:>10}: {:s} = {:s}".format(input_elem['type'], input_elem['name'], input_elem['value']))
                data['fields'][input_elem['name']] = input_elem['value']


        # this deals with multiple lines
        line_select = re.search('<select.*?name.*?=.*?"(.+?)"', line)
        if (line_select):
            l3_select2 = re.search('<select.*?name.*?=.*?"' + str(line_select.group(1)) + '".*?>(.+?)<\/select>', form3_inner_content, re.DOTALL)
            if (l3_select2):
                l3_select3 = handle_unicode(l3_select2.group(1))
            else:
                logging.error("Found select field (" + str(line_select.group(1)) + "), but no option field!")
                sys.exit(1)

            l3_select4 = re.search('<option value="([^"]*?)" selected=', l3_select3, re.DOTALL)
            if (l3_select4):
                # found a select option which is preselected
                data['fields'][str(line_select.group(1))] = str(l3_select4.group(1))
            else:
                l3_select5 = re.search('.*?<option.*?value="(.*?)"', l3_select3, re.DOTALL)
                if (l3_select5):
                    data['fields'][str(line_select.group(1))] = str(l3_select5.group(1))
                else:
                    logging.error("Found select field (" + str(line_select.group(1)) + "), but no option field!")
            #logging.debug("found   select: " + str(line_select.group(1)) + " = '" + str(data['fields'][str(line_select.group(1))]) + "'")


        # FIXME: textarea

    return data




#######################################################################
# main program

# create config directory, if not exist
# path is still hardcoded, don't change it
config_dir = os.path.join(os.environ.get('HOME'), '.imap-mailfilter')
if (os.path.isdir(config_dir) is False):
    try:
        logging.info("Create config directory: " + config_dir)
        os.mkdir(config_dir, 0o700)
    except PermissionError:
        logging.error("Can't create config directory!")
        sys.exit(1)




config = Config()
config.parse_parameters()
config.load_config()

database = Database(config)


# loop over the accounts
# every account needs a new IMAP connection
for account in sorted(config.configfile['accounts']):
    account_enabled = True
    try:
        t = config.configfile['accounts'][account]['enabled']
        t = to_bool(t)
        if (t is False):
            account_enabled = False
    except KeyError:
        pass
    except ValueError:
        logging.error("'enabled' must be a flag")
        sys.exit(1)
    if (account_enabled is True):
        logging.debug("Account: " + account)
        account_action(config, database, account, config.configfile['accounts'][account])





