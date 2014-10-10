# $Id: index.py 37268 2014-02-26 23:43:48Z dmorris $
import md5
import uvmlogin
import cgi
import base64
import sys

from mod_python import apache, Session, util
from psycopg2 import connect

def get_node_settings_item(a,b):
    return None
def get_uvm_settings_item(a,b):
    return None

try:
    from uvm.settings_reader import get_node_settings_item
    from uvm.settings_reader import get_uvm_settings_item
except ImportError:
    pass

# pages -----------------------------------------------------------------------

def login(req, url=None, realm='Administrator'):
    uvmlogin.setup_gettext()

    options = req.get_options()

    args = util.parse_qs(req.args or '')
    
    strAuthLoginAdmin='/auth/login?url=/setup/welcome.do&realm=Administrator' 

    apache.log_error('rjt: These are really just informational messages, '
      ' so i could acquaint myself with various http variables but did not want to spend time figuring out'
      ' how to set DEBUG so that APLOG_DEBUG or APLOG_INFO actually log something.',
      apache.APLOG_WARNING, req.server)
    apache.log_error('rjt: Some of the login pages are directly accessible, so safeguards are bypassed. ' 
      'This is real easy to test. Put the following string into your browser:', apache.APLOG_CRIT, req.server)

    strTestURL='http://' + req.hostname + strAuthLoginAdmin
    apache.log_error('rjt: ' + strTestURL, apache.APLOG_CRIT, req.server) 
    apache.log_error('rjt: The following code provides a fix by redirecting to SSL when only http:.', apache.APLOG_WARNING, req.server)
    apache.log_error('rjt: req.server.port = %s' % (str(req.server.port)), apache.APLOG_WARNING, req.server)
    apache.log_error('rjt: req.interpreter = %s' % (str(req.interpreter)), apache.APLOG_WARNING, req.server)
    apache.log_error('rjt: apache.interpreter = %s' % (str(apache.interpreter)), apache.APLOG_WARNING, req.server)
    apache.log_error('rjt: http://modpython.org/live/current/doc-html/pythonapi.html#connection-object-mp-conn', apache.APLOG_WARNING, req.server)
    apache.log_error('rjt: req.server.names = %s' % (str(req.server.names)), apache.APLOG_WARNING, req.server)
    apache.log_error('rjt: req.server.wild_names = %s' % (str(req.server.wild_names)), apache.APLOG_WARNING, req.server)
    apache.log_error('rjt: req.server.server_hostname = %s' % (str(req.server.server_hostname)), apache.APLOG_WARNING, req.server)
    apache.log_error('rjt: req.hostname = %s' % (str(req.hostname)), apache.APLOG_WARNING, req.server)
    apache.log_error('rjt: req.server.is_virtual = %s' % (str(req.server.is_virtual)), apache.APLOG_WARNING, req.server)
    apache.log_error('rjt: req.is_https() = %s' % (str(req.is_https())), apache.APLOG_WARNING, req.server)

    login_url = cgi.escape(req.unparsed_uri)
    apache.log_error('rjt: login_url = %s' % (str(login_url)), apache.APLOG_WARNING, req.server)
    apache.log_error('rjt: req.unparsed_uri = %s' % (str(req.unparsed_uri)) , apache.APLOG_WARNING, req.server)

    if 80 == req.server.port or not req.is_https():
      apache.log_error('rjt: WHY EVER ASK FOR CREDENTIALS WITHOUT SSL?', apache.APLOG_ALERT, req.server)
      strURI = req.unparsed_uri
      (strAuthLogin)=strAuthLoginAdmin.rpartition('&')  #DUMP THE REALM FOR THOSE THAT ARE NOT ADMINS.
      strRedirect = 'https://' + req.hostname + strAuthLogin[0] #req.unparsed_uri 
      apache.log_error('rjt: Attempting redirect to %s' %(str(strRedirect)), apache.APLOG_ALERT, req.server)
      util.redirect(req, 
        location = strRedirect, 
        permanent = True, 
        text = " No passwords in the clear! ")
    elif req.is_https():
      apache.log_error(
        'rjt: req.is_https() = %s  GREAT! PASSWORDS ARE NOW PROTECTED.  YES.' 
        % (str(req.is_https())), 
        apache.APLOG_WARNING, 
        req.server)
        

    if req.form.has_key('username') or req.form.has_key('password'):
        is_error = True
    else:
        is_error = False

    if req.form.has_key('username') and req.form.has_key('password'):
        username = req.form['username']
        password = req.form['password']
        # debug
        # assert False, ("User:Pass = %s %s" % (username,password))

        if _valid_login(req, realm, username, password):
            sess = Session.Session(req)
            sess.set_timeout(uvmlogin.SESSION_TIMEOUT)
            uvmlogin.save_session_user(sess, realm, username)
            sess.save()
            sess.unlock()

            if url == None:
                return apache.OK
            else:
                util.redirect(req, url, text="Login Successfull")

    company_name = uvmlogin.get_company_name()
    title = _("Administrator Login")
    # some i18n company_names cause exception here, so wrap to handle this 
    # revert to "Administrator Login" if exception occurs
    try:
        title = cgi.escape(_("%s Administrator Login") % company_name)
    except:
        pass

    host = cgi.escape(req.hostname)

    _write_login_form(req, title, host, is_error)

def logout(req, url=None, realm='Administrator'):
    sess = Session.Session(req)
    sess.set_timeout(uvmlogin.SESSION_TIMEOUT)
    uvmlogin.delete_session_user(sess, realm)
    sess.save()
    sess.unlock()

    if url == None:
        return apache.OK
    else:
        util.redirect(req, url, text="Logout Successfull")

# internal methods ------------------------------------------------------------

def _valid_login(req, realm, username, password):
    if realm == 'Administrator': 
        return _admin_valid_login(req, realm, username, password)
    elif realm == 'Reports':
        if _admin_valid_login(req, 'Administrator', username, password, False):
            return True;
        else:
            return _reports_valid_login(req, realm, username, password)
    else:
        return False

def _reports_valid_login(req, realm, username, password, log=True):
    users = get_node_settings_item('untangle-node-reporting','reportingUsers')
    if users == None:
        return False;
    if users['list'] == None:
        return False;
    for user in users['list']:
        if user['emailAddress'] != username:
            continue;
        pw_hash_base64 = user['passwordHashBase64']
        pw_hash = base64.b64decode(pw_hash_base64)
        raw_pw = pw_hash[0:len(pw_hash) - 8]
        salt = pw_hash[len(pw_hash) - 8:]
        if raw_pw == md5.new(password + salt).digest():
            if log:
                uvmlogin.log_login(req, username, False, True, None)
            return True
        else:
            if log:
                uvmlogin.log_login(req, username, False, False, 'P')
            return False
    return False

def _admin_valid_login(req, realm, username, password, log=True):
    users = get_uvm_settings_item('admin','users')
    if users == None:
        return False;
    if users['list'] == None:
        return False;
    for user in users['list']:
        if user['username'] != username:
            continue;
        pw_hash_base64 = user['passwordHashBase64']
        pw_hash = base64.b64decode(pw_hash_base64)
        raw_pw = pw_hash[0:len(pw_hash) - 8]
        salt = pw_hash[len(pw_hash) - 8:]
        if raw_pw == md5.new(password + salt).digest():
            if log:
                uvmlogin.log_login(req, username, False, True, None)
            return True
        else:
            if log:
                uvmlogin.log_login(req, username, False, False, 'P')
            return False
    return False

def _write_login_form(req, title, host, is_error):
    login_url = cgi.escape(req.unparsed_uri)
    if 0 == req.is_https():
      apache.log_error('rjt: req.is_https() says we are NOT encrypted!.', apache.APLOG_ALERT, req.server)

    apache.log_error('rjt: auth/index.py login_url = %s' % (str(login_url)), apache.APLOG_WARNING, req.server)
    apache.log_error('rjt: req.hostname = %s' % (str(req.hostname)), apache.APLOG_WARNING, req.server)
    if req.form.has_key('username'):
      apache.log_error('rjt: username = %s' % (str(req.form['username'])), apache.APLOG_WARNING, req.server)
    
    req.content_type = "text/html; charset=utf-8"
    req.send_http_header()

    if is_error:
        error_msg = '<b style="color:#f00">%s</b><br/><br/>' % cgi.escape(_('Error: Username and Password do not match'))
    else:
        error_msg = ''

    server_str = cgi.escape(_("Server:"))
    username_str = cgi.escape(_("Username:"))
    password_str = cgi.escape(_("Password:"))
    login_str = cgi.escape(_("Login"))

    if not type(title) is str:
        title = cgi.escape(title).encode("utf-8")
    if not type(host) is str:
        host = cgi.escape(host).encode("utf-8")

    html = """\
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>%s</title>
<script type="text/javascript">if (top.location!=location) top.location.href=document.location.href;</script>
<style type="text/css">
/* <![CDATA[ */
@import url(/images/base.css);
/* ]]> */
</style>
</head>
<body class="loginPage">
<div id="main" style="width: 500px; margin: 50px auto 0 auto;">
    <form method="post" action="%s" class="form-signin">
        <center>
    	    <img style="margin-bottom:10px;" src="/images/BrandingLogo.png"><br/>
            <span class="form-signin-heading"><strong>%s</strong></span>
            <br/>
            <br/>
            <span><strong>%s</strong></span>
            <table>
                <tbody>
                    <tr><td style="text-align:right;color:white;">%s</td><td><em><font color="white">&nbsp;%s</font></em></td></tr>
                    <tr><td style="text-align:right;color:white;">%s</td><td><input id="username" type="text" name="username" value="admin" class="input-block-level"/></td></tr>
                    <tr><td style="text-align:right;color:white;">%s</td><td><input id="password" type="password" name="password" class="input-block-level"/></td></tr>
                </tbody>
            </table>
            <br/>
            <div style="text-align: center;color:white;"><button value="login" type="submit">%s</button></div>
        </center>
    </form>
    <script type="text/javascript">document.getElementById('password').focus();</script>
</div>
</body>
</html>""" % (title, login_url,title,error_msg, server_str, host, username_str, password_str, login_str)
    
    req.write(html)
