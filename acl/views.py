# coding:utf-8
from django.shortcuts import render_to_response, redirect
from django.template import RequestContext

import base64
import json
import sys
import urllib2

ip_address = ''
username = ''
password = ''

def login(request):
    context = RequestContext(request, {})
    return render_to_response('acl/login.html', context_instance=context)

def logging_in(request):
    global ip_address, username, password
    ip_address = request.POST['ip_address']
    username = request.POST['username']
    password = request.POST['password']
    
    return redirect('acl:list')
    
def list(request):
    ace_dict = get_ace_dict(ip_address, username, password)
    context = RequestContext(request, {'ip_address': ip_address,
                                       'username': username,
                                       'password': password,
                                       'ace_dict': ace_dict,
                                       })
    return render_to_response('acl/list.html', context_instance=context)

def add(request):
    add_ace()
    return redirect('acl:list')

def delete(request):
    delete_ace()
    return redirect('acl:list')

def logout(request):
    context = RequestContext(request, {})
    return render_to_response('acl/login.html', context_instance=context)

#functions
def get_ace_dict(ip_address, username, password):
        
    headers = {'Content-Type': 'application/json'}
    
    api_path = "/api/access/out/outside/rules/"
    url = "https://" + ip_address + api_path
    f = None
    
    req = urllib2.Request(url, None, headers)
    base64string = base64.encodestring('%s:%s' % (username, password)).replace('\n', '')
    req.add_header("Authorization", "Basic %s" % base64string)
    try:
        f = urllib2.urlopen(req)
        status_code = f.getcode()
        if (status_code != 200):
            return 'Error in get. Got status code: '+status_code
        resp = f.read()
        return json.loads(resp)
    finally:
        if f:  f.close()

def add_ace():
    print ""

def delete_ace():
    print ""