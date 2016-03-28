# coding:utf-8
from django.shortcuts import render_to_response, redirect
from django.template import RequestContext

import base64
import json
import urllib2

ip_address = ''
username = ''
password = ''
token = ''
msg1 = ''
msg2 = ''

def login(request):
    context = RequestContext(request, {'msg': msg1,
                                       })
    return render_to_response('acl/login.html', context_instance=context)

def logging_in(request):
    global ip_address, username, password, token
    ip_address = request.POST['ip_address']
    username = request.POST['username']
    password = request.POST['password']
    
    if get_token():
        return redirect('acl:list')
    else:
        return redirect('acl:login')
    
def list(request):
    outside_ace_dict = get_ace_dict("outside")
    malhosts_og_dict = get_og_dict("MALICIOUS_HOSTS")
    context = RequestContext(request, {'ip_address': ip_address,
                                       'outside_ace_dict': outside_ace_dict,
                                       'malhosts_og_dict': malhosts_og_dict,
                                       'msg': msg2,
                                       })
    return render_to_response('acl/list.html', context_instance=context)

def add(request):
    kind = request.POST['kind']
    value = request.POST['value']
    add_no("MALICIOUS_HOSTS", kind, value)
    return redirect('acl:list')

def delete(request):
    kind = request.POST['kind']
    value = request.POST['value']
    delete_no("MALICIOUS_HOSTS", kind, value)
    return redirect('acl:list')

def logout(request):
    delete_token()
    return redirect('acl:login')

#functions
def get_ace_dict(nameif):
        
    headers = {'Content-Type': 'application/json'}
    
    api_path = "/api/access/out/" + nameif + "/rules/"
    url = "https://" + ip_address + api_path
    f = None
    
    req = urllib2.Request(url, None, headers)
    req.add_header("X-Auth-Token", token)
    try:
        f = urllib2.urlopen(req)
        status_code = f.getcode()
        if (status_code != 200):
            return 'Error in get. Got status code: '+status_code
        resp = f.read()
        return json.loads(resp)
    finally:
        if f:  f.close()

def get_og_dict(og_name):
    
    headers = {'Content-Type': 'application/json'}

    api_path = "/api/objects/networkobjectgroups/" + og_name        
    url = "https://" + ip_address + api_path
    f = None
    
    req = urllib2.Request(url, None, headers)
    req.add_header("X-Auth-Token", token)
    try:
        f = urllib2.urlopen(req)
        status_code = f.getcode()
        if (status_code != 200):
            return 'Error in get. Got status code: '+status_code
        resp = f.read()
        return json.loads(resp)
    finally:
        if f:  f.close()

def add_no(og_name, kind, value):
    global msg2
    
    headers = {'Content-Type': 'application/json'}

    api_path = "/api/objects/networkobjectgroups/" + og_name
    url = "https://" + ip_address + api_path
    f = None
    
    put_data = {
      "members.add": [
        {
          "kind": kind,
          "value": value
        }
      ]
    }
    req = urllib2.Request(url, json.dumps(put_data), headers)
    req.add_header("X-Auth-Token", token)  
    req.get_method = lambda: 'PATCH'
    try:
        f = urllib2.urlopen(req)
        status_code = f.getcode()
        if status_code == 204:
            msg2 = ''
            return True
    except urllib2.HTTPError, err:
        msg2 =  "Error received from server. HTTP Status code :"+str(err.code)
        return False
    finally:
        if f:  f.close()

def delete_no(og_name, kind, value):
    global msg2
    
    headers = {'Content-Type': 'application/json'}

    api_path = "/api/objects/networkobjectgroups/" + og_name
    url = "https://" + ip_address + api_path
    f = None
    
    put_data = {
      "members.remove": [
        {
          "kind": kind,
          "value": value
        }
      ]
    }
    req = urllib2.Request(url, json.dumps(put_data), headers)
    req.add_header("X-Auth-Token", token)  
    req.get_method = lambda: 'PATCH'
    try:
        f = urllib2.urlopen(req)
        status_code = f.getcode()
        print "Status code is "+str(status_code)
        if status_code == 204:
            msg2 = ''
            return True
    except urllib2.HTTPError, err:
        msg2 =  "Error received from server. HTTP Status code :"+str(err.code)
        return False
    finally:
        if f:  f.close()

def get_token():
    global token, msg1
    
    headers = {'Content-Type': 'application/json'}

    api_path = "/api/tokenservices"
    url = "https://" + ip_address + api_path
    f = None
    
    post_data = ''
    req = urllib2.Request(url, json.dumps(post_data), headers)
    base64string = base64.encodestring('%s:%s' % (username, password)).replace('\n', '')
    req.add_header("Authorization", "Basic %s" % base64string)   
    try:
        f  = urllib2.urlopen(req)
        status_code = f.getcode()
        if status_code == 204:
            headers = f.info()
            token = headers.getheader('X-Auth-Token')
            msg1 = ''
            return True
    except urllib2.HTTPError, err:
        msg1 = "Error received from server. HTTP Status code :"+str(err.code)
        return False
    finally:
        if f:  f.close()
        
def delete_token():
    global token
    
    headers = {'Content-Type': 'application/json'}

    api_path = "/api/tokenservices/" + token
    url = "https://" + ip_address + api_path
    f = None
    
    post_data = ''
    req = urllib2.Request(url, json.dumps(post_data), headers)
    req.add_header("X-Auth-Token", token)  
    req.get_method = lambda: 'DELETE'
    
    f  = urllib2.urlopen(req)
    status_code = f.getcode()

    token = ''
    if f:  f.close()    
    
    