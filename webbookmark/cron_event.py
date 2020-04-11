#!/user/bin/env python3
# -*- coding:utf-8 -*-


"""
定时事件，每小时运行一次
删除已经到期的限制IP
"""

from time import time as t 
import sqlite3

db_addr="/media/data/编程/Project/webbookmark/db.sqlite3"


if __name__=="__main__":
    now=round(t())

    cmd="delete from user_iprecord where date_available <={}"

    conn=sqlite3.connect(db_addr)
    c=conn.cursor()
    c.execute(cmd.format(now))
    c.commit()
    conn.close()
