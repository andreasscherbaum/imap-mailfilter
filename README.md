# IMAP Mailfilter

filter emails in IMAP accounts

# Motivation

Mailfilters are possible on the server-side and on the client-side.

Client-side filters are usually built-in into your [MUA](https://en.wikipedia.org/wiki/Email_client), and only runs when your client program is running, and your computer is online. That is a problem if you use multiple clients (like on your computer and your mobile device).

Server-side filters are built-in into the [MTA](https://en.wikipedia.org/wiki/Message_transfer_agent), and run when the email arrives and before it is delivered to the users mailbox. One example is [Sieve](https://en.wikipedia.org/wiki/Sieve_(mail_filtering_language)).

And then there are email hosting solutions which do not allow server-side mailfilters, and running a client-side filter is not always feasible. There are solutions out there which run on a server somewhere else, one example is [lefcha](https://github.com/lefcha/imapfilter) - however lefcha requires you to write [Lua](https://en.wikipedia.org/wiki/Lua_(programming_language)) code for your filters.

Something more easy is required.

# Usage

IMAP Mailfilter requires Python3 installed, and a number of additional modules (yaml, sqlite3, imaplib, email, smtplib, urllib). No coding knowledge is required for the configuration.

```
./imap-mailfilter.py -v -c test.yaml
```

A configuration file is requires, and is specified using the _-c_ option. Additionally, more verbose output can be enabled using _-v_, or the program can be more quiet using _-q_.


# Configuration file

The file format for the configuration file is [YAML](https://en.wikipedia.org/wiki/YAML).

## Header

```
config:
    database: 
accounts:
    # every IMAP account starts with a name
    Test Account 1:
        # the following fields must be provided:
        # imap_server
        # username
        # password
        enabled: true
        imap_server: imap.gmail.com
        smtp_server: smtp.gmail.com
        smtp_port: 465
        username: <IMAP username>
        password: <IMAP password>
        ssl: true

```

Multiple accounts can be specified, every account must have a unique name, and provide:

* enabled: flag, set to _true_ or _false_
* imap_server: the Hostname or IP-address of the IMAP server
* password: IMAP password
* ssl: flag, set to _true_ or _false_

Additionally, for the _forward_ rule a SMTP server can be specified:

* smtp_server: the Hostname or IP-address of the SMTP server
* smtp_port: TCP port

Credentials are taken from IMAP server.


## Rules

The mail rules are nested under the _rules_ section.


```
        rules:
            # every rule must have a name
            # only use [a-zA-Z0-9 @], end the name with a :
            Forward Test:
                enabled: true
```

Every rule must provide a unique name, filter definitions, and actions.

### Filters

```
            Forward Test:
                enabled: true
                filter:
                    folder: "Inbox"
                    subject: "'Test 123'"
```

Every filter must provide a folder (actions on IMAP servers are run on the selected folder). In terms of select, the choice is between:

* subject
* from
* to
* body

The filter clauses should be YAML-escaped: "' ... '". The "" are for YAML itself, the '' are for the lexer in Python.

Every filter clause is run through a lexer, this allows usage of _AND_ and _OR_ keywords.

#### Examples:

This will search for emails with both _Auto_ and _Car_ inside.

```
"'Auto' AND 'Car'"
```

This will search for emails with have either _Auto_ or _Car_ inside.

```
"'Auto' OR 'Car'"
```

#### Combine multiple filters

Filters like _subject_ and _from_ can be used together, and will form an _AND_ search by default. _OR_ can be used as well.



### Actions

After a rule matches emails, defined actions will be run on the emails.


```
                action:
                    action-type: delete
```

#### Action: test

Only for debugging purposes.

```
                action:
                    action-type: test
```


#### Action: delete

This one is easy, it will just delete the email.


```
                action:
                    action-type: delete
```


#### Action: forward

Forwards the email to a specific recipient.


```
                action:
                    action-type: forward
                    recipient: recipient@address
```

The forward address must be defined, and in addition the account configuration must have _smtp_server_ and _smtp_port_ specified.

Note: some email providers like Google do not let you change the sender of the email, unless you verify the email address in your account. The tool will try to set the from address to the original from address in the email, but this might be overridden by Google.


#### Action: mailman2

This handles mails from Mailman2 which request specific actions.


```
                    action-type: mailman2
                    mailman-password: thelistpassword
                    mailman-action: discard
                    mailman-subject: Test
```

The list password must be specified, in order to let the tool handle the email. Also the action must be defined, and can be one of:

* defer
* approve
* reject
* discard

Because of the way Mailman2 works, you have to specify new search rules for the listed mails. The info email does not direct to a specific email which must be handled, but only let's you login into the administration interface, and there you will find all pending emails. Therefore either _mailman-subject_ or _mailman-from_ must be specified to identify the emails which needs to be handled.


#### Action: majordomo

This handles mails from Majordomo which request specific actions.

```
                action:
                    action-type: majordomo
                    action-url: https://listserver/mj/mj_confirm/domain
                    majordomo-action: reject-quiet
```

The _action-url_ part is the URL to the list server, and will be used to identify the full link in the email. The _majordomo-action_ part can be one of:

* accept
* accept-archive
* accept-hide
* reject
* reject-quiet


#### Action: pglister

This handles moderation mails from the PostgreSQL Maílinglist system which request specific actions.

```
                action:
                    action-type: pglister
                    pglister-action: approve
                    pglister-subject: Test
                    pglister-from: sender@address
```

The _pglister-action_ part can be one of:

* approve
* whitelist
* discard
* reject
* cleanup

Where the first four are know actions to the Mailinglist system, and the last is an internal action.

Except for the _cleanup_ action, either _pglister-subject_ or _pglister-from_, or both, must be specified.

The _cleanup_ action will delete old moderation emails, where the token is expired (because someone else might have moderated the email). Make sure that _delete-after_ is set to _false_ for this rule!




### Additional email options

There are two additional options which can be applied to every email which is found by the filters:


#### delete-after

This will delete the email once the action part is completed.

```
                delete-after: true
```


#### remember

This will remember if an email was processed before, and not repeat the action. Useful for forward rules.


```
                remember: false
```


