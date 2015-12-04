#!/usr/bin/env python
#-*- coding:utf-8 -*-
import nmap
import threading
import smtplib
import string
from email.mime.text import MIMEText
from email.header import Header
import sys
#防止linux下中文出问题
reload(sys)
sys.setdefaultencoding('utf-8')

#设置白名单接口
PortList=[xxx]

#设置收件人列表:多个需要用逗号隔开,如:['xxx@xxxx.com','4153@qq.com','http@163.com']
MailList=['xxx@lxxxx.com']

#定义个全局变量以接受scan1函数中的变量
result = ''

#总共执行的主机数
num=file('ip.txt','r')
HostNum=len(num.readlines())
num.close()

#定义发邮件函数
def SendMail(sender,receiver,subject,content,smtpserver,smtpuser,smtppass):
  msg = MIMEText(content,'html','utf-8')
  msg['Subject'] = Header(subject, 'utf-8')
  msg['From'] = '<%s>' % sender 
  msg['To'] = ";".join(receiver)
  try: 
    smtp = smtplib.SMTP()
    smtp.connect(smtpserver)
    smtp.login(smtpuser, smtppass)
    smtp.sendmail(sender, receiver, msg.as_string())
    smtp.quit()
  except Exception,e:
      print e
#定义扫面端口函数,默认端口是1-65535
def scan1(ip,port='1-65535'):
  nm = nmap.PortScanner()
  nm.scan(ip,port)
  global result
  result = result + "<h2>ip地址: %s</h2><hr>" %(ip)
  for proto in nm[ip].all_protocols():
    lport = nm[ip][proto].keys()
   # print lport
    lport.sort()
    for port in lport:
      if port in PortList:
        info = '<strong><font color=green>Info:正常开放端口:</font></strong>&nbsp;&nbsp;'
        portinfo='%s<strong> port </strong>: %s&nbsp;&nbsp;<strong>state</strong>: %s &nbsp;&nbsp;<strong>product</strong>: %s<br>' %(info,port,nm[ip][proto][port]['state'],nm[ip]['tcp'][port]['name'])
        result = result + portinfo
      else:
        info = '<strong><font color=red>Info:非预期端口</font></strong>&nbsp;&nbsp;'
        portinfo='%s<strong> port </strong>: %s&nbsp;&nbsp;<strong>state</strong>: %s &nbsp;&nbsp;<strong>product</strong>: %s<br>' %(info,port,nm[ip][proto][port]['state'],nm[ip]['tcp'][port]['name'])
        result = result + portinfo 
  return result
#定义多线程扫描
def main():
  threads=[]
  #使用的ip列表文件
  f=file('./ip.txt','rU')
  nloops = len(f.readlines())
  f.seek(0)
  global ErrorNum
  global CurNum
  global ErrHostList
  ErrorNum=0
  CurNum=0
  ErrHostList = ''
  for i in f.readlines():
    t=threading.Thread(target=scan1,args=(i.strip(),))
    threads.append(t)
  for i in range(nloops):
    try:
      threads[i].start()
    except Exception,e:
      ErrorNum=ErrorNum+1
      ErrHostList = ErrHostList + '%s' % num[ip]
    else:
      CurNum=CurNum+1
  for i in range(nloops):
    threads[i].join()
  f.close()
if __name__ == "__main__":
  main()
  sender = 'xxx@xxxxx.com'
  receiver = MailList
  #邮件主题,如:大闹天宫端口扫描
  subject = '诸神端口扫描'
  smtpserver = 'smtp.xxxx.com'
  smtpuser = 'xxxx@xxxx.com'
  smtppass = 'xxxx'
  #mailcontent = '<h1>共执行%s 台主机<h1><br>' % HostNum + '<h2>成功%s台<h2><br>' % CurNum + '<h2>失败%s台<h2><br>' % ErrorNum + '<h2>失败的ip为:%s<h2><br>' % ErrHostList + result 
  mailcontent = '<h1>共执行%s 台主机</h1>' % HostNum + '<h2>成功%s台</h2>' % CurNum + '<h2>失败%s台</h2>' % ErrorNum + '<h2>失败的ip为:%s</h2><hr>' % ErrHostList + result 
  #print mailcontent
  SendMail(sender,receiver,subject,mailcontent,smtpserver,smtpuser,smtppass)
  #print result
