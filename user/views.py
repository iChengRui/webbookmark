from json import loads
from time import time as t
from hashlib import sha256
import lxml.html as ht
import re
import os
import gzip

from django.shortcuts import render
from django.template.context import RequestContext 
from django.views.decorators.csrf import csrf_exempt,csrf_protect
from django.db.models import F
from django.contrib.auth import logout, authenticate, login
from django.conf import settings
from django.core.validators import URLValidator
from django.contrib.auth.decorators import login_required
from django.db import IntegrityError, DataError

from . import models 
from .models import MyUser,IPRecord
from django.http.response import HttpResponse,HttpResponseRedirect
from django.contrib.messages.constants import SUCCESS
from django.conf.global_settings import MEDIA_ROOT

URL_CHECK = URLValidator()
CONTENT_MAX_LEN=65536
SALT=settings.SECRET_KEY[::2]
MEDIA_ROOT=settings.MEDIA_ROOT
ONEDAY=86400  # 24*60*60 一天的秒数


U_P_ERR='0' # 用户名或密码错误
SUCCESS='1' # 登录成功
IP_FORBID='2' # 错误失败次数过多，禁止访问
SVR_ERR='3' # 服务器内部故障
U_RPT_ERR='4' # 用户名重复
LEN_ERR='5' # 内容超出允许的最大长度
CNT_ROOT_ERR='6' # 出现多于一个根
FORMAT_ERR='7' # 上传文件格式错误


# 至少一个字母，一个数字，一个特殊字符
pwdpattern = r'^(?=.*?[A-Za-z])(?=.*?[0-9])(?=.*?[^A-Za-z0-9]).{5,12}$'
pwdptn=re.compile(pwdpattern)


gc_verify_container_tag={'li','ul','h5'}
gc_escape_char=re.compile("<|\"|>|'")
gc_url=re.compile(r"^[A-Za-z]+://[A-Za-z0-9-_]+\.[A-Za-z0-9-_%&?/.=]+$")
gc_img=re.compile(r"<img.+?>",re.DOTALL)


m=str.maketrans({'"':"&quot;","'":"&#39;",'<':'&lt;','>':'&gt;','&':'&amp;'})

u=models.MyUser.objects
r=os.remove



def ulogin(req):
    if req.method == "POST":
        username= req.POST['username']
        pwd = req.POST['pwd']
        ip=req.META['REMOTE_ADDR']
        #cron event will be triggered everyhour
        try:
            rec=IPRecord.objects.get(ip=ip)
        except Exception:
            rec=None
        if rec and rec.failure_times>4:
            return HttpResponse(IP_FORBID,content_type='application/json')

        user = authenticate(req,username=username,password=pwd)
        
        msg = None
        if user is None:
            if rec:
                if rec.failure_times==4:
                    date_aval=round(t())+ONEDAY
                    rec.failure_times+=1
                    rec.date_available=date_aval
                else:
                    rec.failure_times+=1
            else:
                date_aval=round(t())+ONEDAY
                rec=IPRecord.objects.create(ip=ip,failure_times=1,date_available=date_aval)
            rec.save()
            return HttpResponse(U_P_ERR,content_type='application/json')
        else:
            login(req, user)
            
            rsp=HttpResponse('"'+uname_m_fname(username)+'"',content_type='application/json')
            # secure 是否仅通过https传输
            rsp.set_cookie('login',1,secure=False)
            
            return rsp


@login_required
def ulogout(req):
    logout(req)
    return HttpResponse(SUCCESS,content_type='application/json')


def uregister(req):
    msg=None
    if req.method == "POST":

        username= req.POST['username']
        pwd = req.POST['pwd']
        pwd2 = req.POST['pwd2']

        name_len=len(username)
        if name_len<5 or name_len>12:
            return HttpResponse(U_P_ERR,content_type='application/json')
        
        if pwd == pwd2 and pwdptn.match(pwd):
            try:
                obj = u.create_user(username=username, password=pwd)
            except IntegrityError as err:
                msg =U_RPT_ERR
            except Exception as err:
                msg =SVR_ERR
            if msg:
                return HttpResponse(msg,content_type='application/json')
            
            obj.save()

            login(req, obj)
            
            rsp=HttpResponse('"'+uname_m_fname(username)+'"',content_type='application/json')
            rsp.set_cookie('login',1,secure=False)
            return rsp
        else:
            return HttpResponse(U_P_ERR,content_type='application/json')
            

@login_required
def udelete(req):
    uname= req.user.username
    user = u.get(username=uname)
    user.delete()
    fname=uname_m_fname(uname)
    try:
        r(MEDIA_ROOT+fname)
    except Exception:
        pass
    return HttpResponse(SUCCESS,content_type='application/json')

def  uname_m_fname(uname):
    """
    将用户名映射成用户拥有的文件名
    """
    if not uname:
        return ''
    
    f=uname+SALT
    s=sha256()
    s.update(f.encode())
    return s.hexdigest()

def escape_char(cnt):
    return cnt.stranslate(m)
    

def verify_html(str_l):
    """
    验证输入的html是否准确
    
    str_l:list,str_l[0] is uploaded html fragment string;str_l[1] is 
        error message(if).
    """
    container=list()
    child_cnt=list()
    cur=list()
    html=ht.fragments_fromstring(str_l[0])
    if len(html) != 1:
        raise ValueError
    html=html[0]
    container.append(html)
    child_cnt.append(1)
    cur.append(0)

    while(container):
        node=container[-1]
        cnt=child_cnt[-1]
        idx=cur[-1]
        if cnt>=idx:
            child=node[idx]
            if child.tag not in gc_verify_container_tag:
                raise ValueError
            c_cnt=len(child)
            if c_cnt>1:
                if child.tag=='ul':
                    container.append(child)
                    child_cnt.append(c_cnt-1)
                    cur[-1]=idx+1
                    cur.append(0)
                else:
                    raise ValueError
            else:
                if child.tag=="h5":
                    if len(child.attrib) or \
                    gc_escape_char.search(child.text):
                        raise ValueError
                elif child.tag=="li":
                    attr=child.attrib
                    child_href=child[0]
                    if len(attr) or child_href.tag!='a':
                        raise ValueError
                    
                    attr=child_href.attrib
                    if len(attr)!=1 or \
                        not attr.has_key("href") or \
                        gc_escape_char.search(child_href.text) or \
                        not gc_url.match(attr["href"]):
                        raise ValueError
                else:    
                    raise ValueError
                cur[-1]=idx+1
        else:
            container.pop()
            child_cnt.pop()
            cur.pop()

def content_update(str_l,username):
    if len(str_l[0])>CONTENT_MAX_LEN:
        str_l.append(LEN_ERR)
        return False
    try:
        verify_html(str_l)
    except ValueError:
        str_l.append(FORMAT_ERR)
        return False
    fname=uname_m_fname(username) 
    with gzip.open(MEDIA_ROOT+fname+".gz", 'wt', 6, encoding='utf8' ) as f:
        f.write(str_l[0])
    str_l.append(fname)
    return True

def verify_bookmark(cnt):
    """
    将浏览器导出的书签（html格式）转换为所需的格式
    """
    html_content=html_content.split('\n')

    
    html_frag=list()
    
    startheader="<ul><h5>"
    endheader="</h5>"
    endheader_tail="</ul>"
    
    starthref='<li><a href="'
    endhref='">'
    endhref_tail='</a>'
    html_content_len=len(html_content)
    
    header_level=0
    j=0
    while(j<html_content_len):
        i=html_content[j].strip('  \n')
        if len(i)<3:
            continue
        if i[:4]=="<DT>":
            #书签或文件夹名
            if i[4:13]=="<A HREF=\"":
                #书签链接
                href_p=i.find('"',15)
                if href_p==-1:
                    raise ValueError
                href=i[13:href_p]
                if not gc_url.match(href):
                    raise ValueError
                #书签名称
                bkmk_name=i.find(">",href_p)
                if bkmk_name==-1:
                    raise ValueError
                bkmk_name=i[bkmk_name+1:-4]
                bkmk_name=escape_char(bkmk_name)
                html_frag.extend((starthref,href,endhref,bkmk_name,endhref_tail))
            elif i[4:7]=="<H3":
            #文件夹名称
                html_frag.append(startheader) 
                h5=i.rfind("</H3>")
                if h5==-1:
                    raise ValueError
                h5=i[8:h5]
                h5=escape_char(h5)
                html_frag.append(h5) 
                html_frag.append(endheader) 
                j+=1
                i=html_content[j].strip('  \n')
                if i!="<DL><p>":
                    raise ValueError
                header_level+=1
            else:
                raise ValueError
        elif i[:5]=="</DL>":
            header_level-=1
            html_frag.append(endheader_tail)
        elif i[:4]=="<H1>":
            html_frag.append(startheader) 
            h5=i.rfind("</H1>")
            header_level+=1
            if h5==-1:
                raise ValueError
            h5=i[4:h5]
            h5=escape_char(h5)
            html_frag.append(h5) 
            html_frag.append(endheader) 
            j+=1
            i=html_content[j].strip('  \n')
            if i!="<DL><p>":
                raise ValueError
        else:
            pass    
        j+=1
    if header_level<1:
        raise ValueError
    else:
        html_frag.append(endheader_tail*header_level)
    return ''.join(html_frag)
    
@login_required
def fupdate(req):
    """
    通过上传文件取得书签
    """
    uf=req.FILES["upfile"]
    content=uf.read().strip()
    uf.close()
    if len(content)<19:
        return HttpResponse(LEN_ERR, content_type='application/json')
    # 去除可能的div
    if content[:4]=="<div":
        div_e=content.find(">")
        if div_e==-1:
            return HttpResponse(FORMAT_ERR, content_type='application/json')
        content=content[div_e+1:-7]
    if content[:4]=="<ul>":
        # 删除img标签
        content=gc_img.sub('',content)
        str_l=[content]
        if content_update(str_l,req.user.username):
            return HttpResponse('"'+str_l[1]+'"', content_type='application/json')
        else:
            return HttpResponse(FORMAT_ERR,content_type='application/json')
    elif content[:9]=="<!DOCTYPE":
        try:
            content=verify_bookmark(content)
        except ValueError:
            return HttpResponse(FORMAT_ERR, content_type='application/json')
        if len(content)>CONTENT_MAX_LEN:
            return HttpResponse(LEN_ERR, content_type='application/json')
        fname=uname_m_fname(req.user.username) 
        with gzip.open(MEDIA_ROOT+fname+".gz", 'wt', 6, encoding='utf8' ) as f:
            f.write(content)
        return HttpResponse('"'+fname+'"', content_type='application/json')
    else:
        return HttpResponse(FORMAT_ERR, content_type='application/json')
    
@login_required
def cupdate(req):
    """
    更新或新建书签
    """
    if req.method=='POST':
        str_l=[]
        str_l.append(loads(req.body))
        if content_update(str_l,req.user.username):
            return HttpResponse(SUCCESS, content_type='application/json')
        else:
            return HttpResponse(str_l[1],content_type='application/json')
            
    elif req.method=='GET':
        fname=uname_m_fname(req.user.username) 
        return HttpResponseRedirect('/owner.html?'+fname)


# TODO 
@login_required
def uupdate(req):
    pass


def user_reset(req, uid):
    pass


def user_reset_req(req):
    pass
