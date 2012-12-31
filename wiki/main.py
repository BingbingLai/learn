#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import webapp2
import re
import jinja2
import hashlib
import hmac
from string import letters
import random
from google.appengine.ext import db

secret="wtf"

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

def valid_username(username):
    return USER_RE.match(username)

def valid_password(password):
    return PASSWORD_RE.match(password)

def valid_email(email):
    return EMAIL_RE.match(email)

def make_cookie_val(val):
    return '%s,%s' % (val,(hmac.new(secret,val).hexdigest()))

def check_cookie_val(cookie_val):
    val=cookie_val.split(',')[0]
    if cookie_val==make_cookie_val(val):
        return val

def make_salt(length=5):
    return ' '.join(random.choice(letters) for x in xrange(length))

def make_pwhash(name,password,salt=None):
    if not salt:
        salt=make_salt()
    return '%s,%s' % (salt,(hashlib.sha256(name+password+salt).hexdigest()))

def check_pw(name,password,pwhash):
    salt=pwhash.split(',')[0]
    return pwhash==make_pwhash(name,password,salt)

class MainHandler(webapp2.RequestHandler):

    def write(self,*a,**aa):
        self.response.out.write(*a,**aa)

    def render_str(self,template,**param):
        t=jinja_env.get_template(template)
        return t.render(param)

    def render(self,template,**bb):
        self.write(self.render_str(template,**bb))

    def set_secure_cookie(self,name,val):
        cookie_val=make_cookie_val(val)
        self.response.headers.add_header('Set-Cookie','%s=%s; path=/' %(name,cookie_val)) 

    def read_cookie(self,name):
        cookie_val=self.request.cookies.get(name)
        return cookie_val and check_cookie_val(cookie_val)

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

class User(db.Model):
    name = db.StringProperty (required=True)
    pwhash = db. StringProperty (required=True)
    email = db.StringProperty ()

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

class FrontPage(MainHandler):
    def get(self):
        self.render('front.html')

class Signup(MainHandler):
    def get(self):
        self.render('signup.html')

    def post(self):
        have_error=False
        un=self.request.get("username")
        pw=self.request.get("password")
        vf=self.request.get("verify")
        em=self.request.get("email")
        error=dict(username=un,email=em)
        
        if not valid_username(un):
            error['error_un']="It's not a valid username!"
            have_error=True

        if not valid_password(pw):
            error['error_pw']="It's not a valid password!"
            have_error=True

        elif vf != pw:
            error['error_vf']="It's not match the password you enter above!"
            have_error=True

        if em and not valid_email(em):
            error['error_em']="It's not a valid email!"
            have_error=True

        if have_error:
            self.render('signup.html',**error)

        else:
            u = User.by_name(un)
            if u==None:
                pwhash = make_pwhash( un, pw)
                user = User( name = un, pwhash = pwhash, email = em )
                user.put()
                self.set_secure_cookie('user_id',str(u.key().id()))
                self.redirect('/')

            else:
                error = 'This user already exist !'
                self.render('signup.html', error_un = error)

class Login(MainHandler):
    def get(self):
        self.render('login.html')
    
    def post(self):
        un = self.request.get('username')
        pw = self.request.get('password')
        u = User.by_name(un)
        if u and check_pw(un,pw,u.pwhash):
            self.set_secure_cookie('user_id', str(u.key().id()))
            self.redirect('/')
        else:
            error="It's invalid !"
            self.render('login.html',error = error)

class logout(MainHandler):
    def  get(self):
        self.response.headers.add_header('Set_Cookie','User_id= ; path= /')
        self.redirect('/')
                   
app = webapp2.WSGIApplication([('/', FrontPage),
                               ('/signup',Signup),
                                ('/login',Login),
                                ],

                                       debug=True)
