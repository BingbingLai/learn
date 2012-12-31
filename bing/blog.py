import os
import webapp2
from xml.dom import minidom
import urllib2
import jinja2
from google.appengine.ext import db

jinja_environment = jinja2.Environment(autoescape=True,
                                       loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))

GMAPS_URL = "http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&"
info_url="http://api.hostip.info/?ip="      

class Handler(webapp2.RequestHandler):
    def write(self,*a,**kw):
        self.response.write(*a,**kw)
    def render_str(self,template,**param):
        t=jinja_environment.get_template(template)
        return t.render(param)
    def render(self,template,**kw):
        self.write(self.render_str(template,**kw))
def gmaps_img(points):
    mark='&'.join('markers=%s,%s' % (p.lat,p.lon) for p in points)
    return GMAPS_URL+mark

def get_ip(ip):
    ip="67.160.207.126"
    ip_url=info_url+ip
    content=None
    try:
        content=urllib2.urlopen(ip_url).read()
    except URLError:
        return
    if content:
        c=minidom.parseString(content)
        a=c.getElementsByTagName('gml:coordinates')
        if a and a[0].childNodes[0].nodeValue:
            lon,lat=a[0].childNodes[0].nodeValue.split(",")
            return db.GeoPt(lat,lon)
        
class Blog(db.Model):
    subject = db.StringProperty(required = True)
    body = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    coords=db.GeoPtProperty()
class MainPage(Handler):
    def render_front(self,subject="",body="",error=""):
        blogs  =  db.GqlQuery("select * from Blog order by created desc ")

        blogs=list(blogs)
        points=filter(None,(bl.coords for bl in blogs))
        img_url=None
        if points:
            img_url=gmaps_img(points)
            
        self.render("bblog.html",subject=subject,body=body,error=error,blogs=blogs,img_url=img_url)
    def get(self):
        self.render_front()

    def post(self):
        subject=self.request.get("subject")
        body=self.request.get("body")
        if subject and body:
            b=Blog(subject=subject,body=body)
            ip = self.request.remote_addr
            coords =get_ip()
            if coords:
                b.coords=coords
            b.put()
            self.redirect("/")
        else:
            error="we need both a subject and a body!"
            self.render_front(subject,body,error)


app = webapp2.WSGIApplication([("/", MainPage)],
                              debug=True)
