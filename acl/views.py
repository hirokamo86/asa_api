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
    outside_ace_dict = get_ace_dict(ip_address, username, password, "outside")
    malhosts_og_dict = get_og_dict(ip_address, username, password, "MALICIOUS_HOSTS")
    context = RequestContext(request, {'ip_address': ip_address,
                                       'username': username,
                                       'password': password,
                                       'outside_ace_dict': outside_ace_dict,
                                       'malhosts_og_dict': malhosts_og_dict,
                                       })
    return render_to_response('acl/list.html', context_instance=context)

def add(request):
    add_no()
    return redirect('acl:list')

def delete(request):
    delete_no()
    return redirect('acl:list')

def logout(request):
    context = RequestContext(request, {})
    return render_to_response('acl/login.html', context_instance=context)

#functions
def get_ace_dict(ip_address, username, password, nameif):
        
    headers = {'Content-Type': 'application/json'}
    
    api_path = "/api/access/out/" + nameif + "/rules/"
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

def get_og_dict(ip_address, username, password, og_name):
    
    headers = {'Content-Type': 'application/json'}

    api_path = "/api/objects/networkobjectgroups/" + og_name        
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

def add_no():
    print ""

def delete_no():
    print ""