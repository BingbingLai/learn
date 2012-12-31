
import os
import webapp2
import jinja2
import re
import hashlib
import hmac
from string import letters
import random
from google.appengine.ext import db

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

def valid_username(username):
    return USER_RE.match(username)

def valid_password(password):
    return PASSWORD_RE.match(password)

def valid_email(email):
    return EMAIL_RE.match(email)

jinja_environment = jinja2.Environment(autoescape=True,
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))

secret='i3wayne'

def make_cookie_val(val):
    return '%s|%s' %(val, hmac.new(val, secret).hexdigest())

def check_cookie_val(cookie_val):
    val=cookie_val.split('|')[0]
    if cookie_val==make_cookie_val(val):
        return val

def make_salt(length = 6):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name,pw,salt=None):
    if not salt:
        salt=make_salt()
    pw_hash = hashlib.sha256(name+pw+salt).hexdigest()
    return '%s,%s' % (pw_hash,salt)

def valid_pw(name,pw,h):
    salt=h.split(',')[1]
    return h==make_pw_hash(name,pw,salt)
    
class MainHandler(webapp2.RequestHandler):
    def write(self,*a,**aa):
        self.response.out.write(*a,**aa)

    def render_str(self,template,**param):
        t=jinja_environment.get_template(template)
        return t.render(param)

    def render(self,template,**bb):
        self.write(self.render_str(template,**bb))

    def set_secure_cookie(self,name,val):
        cookie_val=make_cookie_val(val)
        self.response.headers.add_header('Set_Cookie','%s=%s; Path=/' % (name,cookie_val))

    def read_secure_cookie(self,name):
        cookie_val=self.request.cookies.get(name)
        return cookie_val and check_cookie_val(cookie_val)
      
class Mainpage(MainHandler):
    def get(self):
        self.render("mainpage.html")

class Blog(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def signup(cls,name,pw,email=None):
        pw_hash=make_pw_hash(name,pw)
        return User(name=name,pw_hash=pw_hash,email=email)
    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u
      
        
class Signup(MainHandler):
    def get(self):
        self.render("signup.html")
        
    def post(self):
        have_error=False
        un = self.request.get("username")
        pw = self.request.get("password")
        vf = self.request.get("verify")
        em = self.request.get("email")
        error=dict(username=un,email=em)
        
        if not valid_username(un):
            error['user_error']="That is not a valid username !"
            have_error=True
        if not valid_password(pw):
            error['pass_error']="That is not a valid password !"
            have_error=True
        elif vf != pw:
            error['verify_error']="That doesn't match the password"
            have_error=True
        if em and not valid_email(em):
            error['email_error']="That is not a valid email !"
            have_error=True
        if have_error:
            self.render("signup.html",**error)



class Login(MainHandler):
    def get(self):
        self.render("login.html")

    def post(self):
        un=self.request.get("username")
        pw=self.request.get("password")
        user=User.by_name(un)

        if user and valid_pw(un,pw,user.pw_hash):
            self.set_secure_cookie('user_id',str(user.key().id()))
            self.redirect("/welcome?username="+un)

        else:
            error="It's invalid!"
            self.render("login.html",error=error)

class Logout(MainHandler):
    def get(self):
        self.response.headers.add_header('Set-Cookie','user_id=; Path=/')
        self.redirect('/')
        

class Welcome(MainHandler):
    def get(self):
        blogs = db.GqlQuery("select * from Blog order by created desc")
        un=self.request.get("username")
        if valid_username(un):
            self.render("welcome.html",username=un,blogs=blogs)
        else:
            self.redirect('/')
            
    def post(self):
        un=self.request.get("username")
        sb=self.request.get("subject")
        ct=self.request.get("content")
        if sb and ct:
            b = Blog(content=ct,subject=sb)
            b.put()
            self.redirect('/welcome/%s' % str(b.key().id()))
        else:
            self.render("welcome.html",username=un,
                        error="we need both subject and content!")

class Postpage(MainHandler):
    def get(self,post_id):
        key=db.Key.from_path('Blog',int(post_id))
        post=db.get(key)

        if not post:
            self.error(404)
            return

        self.render("post.html",post=post)
        
app = webapp2.WSGIApplication([('/', Mainpage),
                               ('/welcome',Welcome),
                               ('/signup',Signup),
                               ('/login',Login),
                               ('/logout',Logout),
                               ('/welcome/([0-9]+)',Postpage)],
                                debug=True)
