#!/usr/bin/env python
"""
给html中的ul、li添加id属性
"""

src="/media/data/编程/Project/webbookmark/backups/bookmark.html"
dest="/media/data/编程/Project/webbookmark/backups/bookmark_with_id.html"

if __name__=="__main__":
    f=open(src,'rt')
    src_c=f.read()
    f.close()
    
    id_n=1
    last_p=0
    ul_s=li_s=0
    li_ul=False #li标签出现在ul前面
    p=list()
    
    li_s=src_c.find("<li",last_p)
    
    while(ul_s!=-1 or li_s!=-1):
        if not li_ul:
            ul_s=src_c.find("<ul",last_p)
        else:
            li_s=src_c.find("<li",last_p)
            
        if ul_s!=-1 and (ul_s<li_s  or li_s==-1):
            li_ul=False
            ul_s+=3
            p.append(src_c[last_p:ul_s])
            p.append(' id="'+str(id_n)+'"')
            id_n+=1
            last_p=ul_s
        elif li_s!=-1 and (li_s<ul_s or ul_s==-1):
            li_ul=True
            li_s+=3
            p.append(src_c[last_p:li_s])
            p.append(' id="'+str(id_n)+'"')
            id_n+=1
            last_p=li_s
            
    # 结尾部分
    p.append(src_c[last_p:])
    f=open(dest,"w")
    f.write("".join(p))
    f.close()
    
        