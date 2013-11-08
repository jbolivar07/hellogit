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
import webapp2
import os
import jinja2
import random
import string
import hashlib
import re
import httplib
import json


from google.appengine.ext import db

def user_validate(username=""):
    conn = httplib.HTTPConnection("justiceleaguevstheavengers.host22.com")
    query = "/get_user.php?username=%s" % username
    conn.request("GET", query)
    r1 = conn.getresponse()
    data = r1.read()
    conn.close()
    m=re.findall(r'''{"resultQuery":\[{"password":".+","status":".+"}\]}''', data)
    try:
        j=json.loads(m[0])
        if(j['resultQuery'][0]['password'] <> '' ):
            return(j['resultQuery'][0]['password'],j['resultQuery'][0]['status'])
        else:
            return None
    except:
        return None


def get_latitude_altitude(ip="8.8.8.8"):
    conn = httplib.HTTPConnection("ipinfo.io")
    query = "/%s" % ip
    conn.request("GET", query)
    r1 = conn.getresponse()
    data = r1.read()
    try:
        j=json.loads(data)
        return int(j['loc'][0]),int(j['loc'][1])
    except:
        return get_latitude_altitude()



def new_user(username,password,name,ip):
    #(latitude,longitude) = get_latitude_altitude(ip)
    conn = httplib.HTTPConnection("justiceleaguevstheavengers.host22.com")
    query = "/create_user.php?username=%s&name=%s&password=%s&longitude=%s&latitude=%s&id_character=%s&score=%s" % (username,name,password,72,70,"superman",1)
    conn.request("GET", query)
    r1 = conn.getresponse()
    data = r1.read()
    conn.close()
    return None




jinja_env = jinja2.Environment(autoescape=True,
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)



def make_salt():
    salida=string.letters
    salida=re.findall('[a-zA-Z]',salida)
    random.shuffle(salida)

    return ''.join(salida[0:5])


def make_pw_hash(name,pw,salt=None):
    if not salt:
        salt=make_salt()
    h=hashlib.sha256(name+pw+salt).hexdigest()
    return '%s|%s'% (h,salt)


def valid_pw(name,pw,h):
    salt=h.split('|')[1]
    return h==make_pw_hash(name,pw,salt)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

NAME_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_name(name):
    return not email or EMAIL_RE.match(email)



def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class MainPage(BlogHandler):
    def get(self):        
        self.write('Hello Udacity!')


    
class BlogFront(BlogHandler):
    def get(self):
        self.render('BLOG_Juego.html')
            


class MainPagecookie(BlogHandler):

    def get(self):
        self.render('sign_up.html',username="",email="",error_username="",error_password=""
                   ,error_verify="",error_email="")
        
    def post(self):

        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        name = self.request.get('name')

        error_username=""
        error_password=""
        error_verify=""
        have_error=False
             

        if not valid_username(username):
            error_username="no es un usuario valido!"
            username=""
            have_error=True


        elif not valid_password(password):
            error_password="no es una clave valida!"
            have_error=True


        elif password != verify:
            error_verify="no coinciden las claves!"
            have_error=True

        if have_error:

            self.render('sign_up.html',username=username,name=name,error_password=error_password,
                error_username=error_username,error_verify=error_verify)

            
        else:          
            new_user(username,password,name,self.request.remote_addr)
            self.render("Estadisticas.html",user=username)



            

class LoginPage(BlogHandler):
    
    def get(self):
        self.render("Login.html")

    def post(self):

        username  = self.request.get("username")
        password  = self.request.get("password")
        local_val = user_validate(username)

        if(local_val != None):
            if(local_val[0]==password):
                self.render("Estadisticas.html",user=username)
            else:
                self.render("Login.html",error_username="Usuario Invalido")

                
        else: 
            self.render("Login.html",error_username="Usuario Invalido")               
                
        

        


app = webapp2.WSGIApplication([('/', BlogFront),
                               ('/signup', MainPagecookie),
                               ('/login', LoginPage)],
                              debug=True)
