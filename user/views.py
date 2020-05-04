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
from django.db import IntegrityError, DataError, transaction
from django.http.response import HttpResponse,HttpResponseRedirect
from django.contrib.messages.constants import SUCCESS
from django.conf.global_settings import MEDIA_ROOT

from . import models 
from .models import MyUser,IPRecord

URL_CHECK = URLValidator()
CONTENT_MAX_LEN=65536
SALT=settings.SECRET_KEY[::2]
MEDIA_ROOT=settings.MEDIA_ROOT
ONEDAY=86400  # 24*60*60 一天的秒数
CHK_LEN=6  # 用于验证文件名是否为访问者所有的长度，部分检验，可调整


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

#directory start tail pattern
dpattren='</ul|<ul'
dptn=re.compile(dpattren)


gc_verify_container_tag={'li','ul','h5'}
gc_escape_char=re.compile("<|\"|>|'")
# gc_url=re.compile(r"^[A-Za-z]+://[A-Za-z0-9-_]+\.[A-Za-z0-9-_%&?/.=#]+$")
gc_img=re.compile(r"<img.+?>",re.DOTALL)
gc_a_target=re.compile(r"target\s*?=.+?_blank\s*?\"|'",re.DOTALL|re.A|re.I)


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
                    with transaction.atomic(None, False):
                        rec.failure_times+=1
                        rec.date_available=date_aval
                        rec.save()
                else:
                    with transaction.atomic(None, False):
                        rec.failure_times+=1
                        rec.save()
            else:
                date_aval=round(t())+ONEDAY
                with transaction.atomic(None, False):
                    rec=IPRecord.objects.create(ip=ip,failure_times=1,date_available=date_aval)
                    rec.save()
            return HttpResponse(U_P_ERR,content_type='application/json')
        else:
            login(req, user)
            fname=uname_m_fname(username)
            rsp=HttpResponse('"'+fname+'"',content_type='application/json')
            # secure 是否仅通过https传输
            rsp.set_cookie('login',fname[:CHK_LEN],secure=False)
            
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
                with transaction.atomic(None, False):
                    obj = u.create_user(username=username, password=pwd)
                    obj.save()
            except IntegrityError as err:
                msg =U_RPT_ERR
            except Exception as err:
                msg =SVR_ERR
            if msg:
                return HttpResponse(msg,content_type='application/json')

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
    return cnt.translate(m)
    

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
                        not URL_CHECK(attr["href"]):
                        # not gc_url.match(attr["href"]):
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
    html_content=cnt.split('\n')

    html_frag=list()
    
    startheader="<ul><h5>"
    endheader="</h5>"
    endheader_tail="</ul>"
    
    starthref='<li><a href="'
    endhref='">'
    endhref_tail='</a></li>'
    html_content_len=len(html_content)
    
    header_level=0
    j=0
    while(j<html_content_len):
        i=html_content[j].strip('  \n')
        if len(i)<3:
            j+=1
            continue
        if i[:4]=="<DT>":
            #书签或文件夹名
            if i[4:13]=="<A HREF=\"":
                #书签链接
                href_p=i.find('"',15)
                if href_p==-1:
                    raise ValueError
                href=i[13:href_p]
                # if href[-1]=='/':
                #     href=href[:-1]
                # if not gc_url.match(href):
                # if not URL_CHECK(href):
                try:
                    URL_CHECK(href)
                except Exception:
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
                h5_start=i.find(">",7) 
                h5=i.rfind("</H3>")
                if h5==-1 or h5_start==-1 or h5_start>h5:
                    raise ValueError
                h5=i[h5_start+1:h5]
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
            while True:
                j+=1
                i=html_content[j].strip('  \n')
                if not i:
                    continue
                elif i!="<DL><p>":
                    raise ValueError
                else:
                    break
        else:
            pass    
        j+=1
    if header_level<0:
        # print("header_level:"+str(header_level))
        # print(''.join(html_frag))
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
    content=uf.read().strip().decode(encoding="utf-8")
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
        # 删除a标签的target属性
        content=gc_a_target.sub('',content)
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

def find_str(array:list,s:str,start=0,start_s=0):
    """
    从list array中找到s，返回位置，和s所在的位置
    start为 list开始搜寻的起始位置
    start_s 为item开始搜寻的起始位置
    """
    idx=0
    first=True
    
    idx_s=array[start].find(s,start_s)
    if idx_s!=-1:
        return (idx+start,idx_s)
    
    idx+=1
    for j in array[start+1:]:
        idx_s=j.find(s)
        if idx_s!=-1:
            return (idx+start,idx_s)
        idx+=1
    return(-1,-1)

@login_required
def piece_cupdate(req):
    try:
        c=loads(req.body)
    except Exception:
        return HttpResponse(FORMAT_ERR, content_type='application/json')
        
    if not isinstance(c,list):
        return HttpResponse(FORMAT_ERR, content_type='application/json')
    
    err_itm=list()
    old_c=list()
    f_count=-1
    fname=MEDIA_ROOT+uname_m_fname(username) +".gz"
    
    with gzip.open(fname, 'rt', 6, encoding='utf8') as f:
        old_c.append(f.read())

    for i in c:
        f_count+=1
        if not (isinstance(i,list) 
                and isinstance(i[0], int) and i[0]>0
                and isinstance(i[1], int) and 7>i[1]>0):
           err_itm.append(str(f_count))
           continue
       
        kind=i[1]
        if kind==1 or kind==4:
            #1.新增链接 4.新增文件夹
            if gc_escape_char.search(i[2]) or len(i)<5 \
                or not isinstance(i[4], int) or i[4]<=0:
                err_itm.append(i[0]) 
                continue
            
            if kind==1:
                try:
                    URL_CHECK(i[3])
                except Exception:
                    err_itm.append(i[0]) 
                    continue
                new_itm="<li id=\""+str(i[0])+'"'+"><a href=\""+i[3]+'">'+i[2]+"</a></li>"
            else:
                new_itm="<ul id=\""+str(i[0])+'"'+"><h5>"+i[2]+"</h5></ul>"
                
            
            s="id=\""+str(i[4])+'"'
            idx,idx_s=find_str(old_c,s)
            
            if idx==-1:
                err_itm.append(i[0]) 
                continue
            # 找到结尾 </h5>
            idx,idx_s=find_str(old_c,"</h5>",idx,idx_s)
            # TODO内部格式错误
            if idx==-1:
                err_itm.append(i[0]) 
                continue
            
            if old_c[idx][-5:]!="</h5>":
                itm0,itm1=old_c[idx][:idx_s+6],old_c[idx][idx_s+6:]
                del old_c[idx]       
                old_c[idx:idx]=itm0,new_itm,itm1
            else:
                idx+=1
                old_c[idx:idx]=new_itm
            
        elif kind==2:
            # 2.修改链接
            s="id=\""+str(i[4])+'"'
            idx,idx_s=find_str(old_c,s)
            
            if idx==-1:
                err_itm.append(i[0]) 
                continue
            
            pieces=list()
            itm=old_c[idx]
            idx_e=itm.find("</li>")
            itm0,itm1=itm[:idx_e+5],itm[idx_e+5:]
            idx_href=0
            # 修改链接名称
            if i[3]:
                try:
                    URL_CHECK(i[3])
                except Exception:
                    err_itm.append(i[0]) 
                    continue
                idx_href=itm0.find("href=\"",idx)
                pieces.extend([item0[:idx_href+5],i[3],"\">"])
            else:
                pieces.append(item0)   
            # 修改文件名
            if i[2]:
                if gc_escape_char.search(i[2]) or len(i)<5:
                    err_itm.append(i[0]) 
                    continue
                if idx_href:
                    pieces.extend([i[2],'</a></li>'])
                else:
                    idx_label=itm0[:-6].rfind('>',idx)
                    # TODO 内部格式错误
                    if idx_label==-1:
                        err_itm.append(i[0]) 
                        continue
                    pieces.extend([itm0[:idx_label+1],i[2],'</a></li>'])
            
            pieces.append(itm1)
            del old_c[idx]
            old_c[idx:idx]=pieces
        elif kind==3:
            # 3.删除链接
            s="id=\""+str(i[4])+'"'
            idx,idx_s=find_str(old_c,s)
            
            if idx==-1:
                err_itm.append(i[0]) 
                continue
            itm=old_c[idx]
            itm0=itm.rfind('<li',idx_s-5,idx_s)
            itm1=itm.find('</li>',idx_s)
            # TODO 内部格式错误
            if itm0==-1 or itm1==-1:
                err_itm.append(i[0]) 
                continue
            
            itm0,itm1=itm[:itm0],itm[itm1+5:]
            del old_c[idx]
            old_c[idx:idx]=(itm0,itm1)
        elif kind==5:
            # 5.修改文件夹
            if gc_escape_char.search(i[2]) or len(i)<5:
                err_itm.append(i[0]) 
                continue
            
            s="id=\""+str(i[4])+'"'
            idx,idx_s=find_str(old_c,s)
            
            # TODO 内部格式错误
            if idx==-1:
                err_itm.append(i[0]) 
                continue
            # 找到开头 <h5>
            idx,idx_s=find_str(old_c,"<h5>",idx,idx_s)
            # TODO内部格式错误
            if idx==-1:
                err_itm.append(i[0]) 
                continue
            itm=old_c[idx]
            idx_tail=itm.find("</h5>",idx_s)
            itm0,itm1=itm[:idx_s],itm[idx_tail+5:]
            new_itm="<h5>"+i[2]+"</h5>"
            del old_c[idx]
            old_c[idx:idx]=itm0,new_itm,itm1
            
        elif kind==6:
            # 6.删除文件夹
            s="id=\""+str(i[0])+'"'
            header,header_s=find_str(old_c,s)
            if header_s==-1:
                err_itm.append(i[0]) 
                continue
            
            #<ul id=
            header_s=old_c[header].find("<ul" ,max(header_s-5,0),header_s)
            deepth=0
            # TODO内部格式错误
            if header_s==-1:
                err_itm.append(i[0]) 
                continue
            itm0,itm1=old_c[header][:header_s],old_c[header][header_s:]
            old_c[header:header]=itm0,itm1
            header+=1
            tail=0
            tail_s=0
            finished=False
            for i in old_c[header:]:
                for j in dptn.finditer(i):
                    if j.group(0)=='<ul':
                        deepth+=1
                    else:
                        deepth-=1
                    if deepth==0:
                        finished=True
                        tail_s=j.start()
                        break
                if finished:
                    break
                tail+=1
            # FIXIT
            itm0,itm1=old_c[tail][:tail_s+4],old_c[tail][tail_s+4:]
            old_c[tail:tail]=itm0,itm1
            del old_c[header:tail+1]
    with gzip.open(fname, 'wt', 6, encoding='utf8') as f:
           f.write("".join(old_c)) 
    return HttpResponse(dumps(err_itm), content_type='application/json')
# TODO 
@login_required
def uupdate(req):
    pass


def user_reset(req, uid):
    pass


def user_reset_req(req):
    pass
