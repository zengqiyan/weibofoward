# -*- coding: utf-8 -*-
########################
# author:kyle
# date:2018/1/22
#
########################

import sys
import urllib
import urllib.request as urllib2
import http.cookiejar as cookielib
import base64
import re
import json
import rsa
import binascii
from bs4 import BeautifulSoup
import configparser
import time
# 自动转发抽奖微博
class weiboFoward:
    lastUids=[];
    lastWids=[];
    def enableCookies(self):
        # 获取一个保存cookies的对象
        cj = cookielib.CookieJar()
        # 将一个保存cookies对象和一个HTTP的cookie的处理器绑定
        cookie_support = urllib2.HTTPCookieProcessor(cj)
        # 创建一个opener,设置一个handler用于处理http的url打开
        opener = urllib2.build_opener(cookie_support, urllib2.HTTPHandler)
        # 安装opener，此后调用urlopen()时会使用安装过的opener对象
        urllib2.install_opener(opener)

        # 预登陆获得 servertime, nonce, pubkey, rsakv

    def getServerData(self):
        url = 'http://login.sina.com.cn/sso/prelogin.php?entry=weibo&callback=sinaSSOController.preloginCallBack&su=ZW5nbGFuZHNldSU0MDE2My5jb20%3D&rsakt=mod&checkpin=1&client=ssologin.js(v1.4.18)&_=1442991685270'
        data = urllib2.urlopen(url).read()
        data = str(data, encoding='utf-8')
        p = re.compile('.*\((.*)\).*')
        json_data = p.search(data).group(1)
        data = json.loads(json_data)
        servertime = str(data['servertime'])
        nonce = data['nonce']
        pubkey = data['pubkey']
        rsakv = data['rsakv']
        return servertime, nonce, pubkey, rsakv


            # 获取加密的密码

    def getPassword(self, password, servertime, nonce, pubkey):
        rsaPublickey = int(pubkey, 16)
        key = rsa.PublicKey(rsaPublickey, 65537)  # 创建公钥
        message = str(servertime) + '\t' + str(nonce) + '\n' + str(password)  # 拼接明文js加密文件中得到
        passwd = rsa.encrypt(bytes(message,"utf-8"), key)  # 加密
        passwd = binascii.b2a_hex(passwd)  # 将加密信息转换为16进制。
        return passwd

        # 获取加密的用户名

    def getUsername(self, username):
        username_ = urllib.parse.quote(username)
        username = base64.b64encode(bytes(username_,'utf-8'))[:-1]
        return username

        # 获取需要提交的表单数据

    def getFormData(self, userName, password, servertime, nonce, pubkey, rsakv):
        userName = self.getUsername(userName)
        psw = self.getPassword(password, servertime, nonce, pubkey)

        form_data = {
            'entry': 'weibo',
            'gateway': '1',
            'from': '',
            'savestate': '7',
            'useticket': '1',
            'pagerefer': 'http://weibo.com/p/1005052679342531/home?from=page_100505&mod=TAB&pids=plc_main',
            'vsnf': '1',
            'su': userName,
            'service': 'miniblog',
            'servertime': servertime,
            'nonce': nonce,
            'pwencode': 'rsa2',
            'rsakv': rsakv,
            'sp': psw,
            'sr': '1366*768',
            'encoding': 'UTF-8',
            'prelt': '115',
            'url': 'http://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack',
            'returntype': 'META'
        }
        formData = urllib.parse.urlencode(form_data)
        return formData

        # 登陆函数

    def login(self, username, psw):
        self.enableCookies()
        url = 'http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.18)'
        servertime, nonce, pubkey, rsakv = self.getServerData()
        formData = bytes(self.getFormData(username, psw, servertime, nonce, pubkey, rsakv),'utf-8')
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0'}
        req = urllib2.Request(
            url=url,
            data=formData,
            headers=headers
        )
        result = urllib2.urlopen(req)
        text = str(result.read(), encoding='gbk')
        # 还没完！！！这边有一个重定位网址，包含在脚本中，获取到之后才能真正地登陆
        p = re.compile('.*location\.replace\(\'(.*)\'\).*')
        login_url = p.search(text).group(1)
        # 由于之前的绑定，cookies信息会直接写入
        urllib2.urlopen(login_url)
        print("Login success!")


            # 访问主页，把主页写入到文件中

        #fp_raw = open("d://weibo.html", "w+",encoding='utf-8')
        #fp_raw.write(text)
        #fp_raw.close()
        # print text

    def foward(self,wbid):
        form_data = {
            "mid":wbid,
            "style_type": 1,
            "reason": "转发微博",
            "_t":0
        }
        formData = bytes(urllib.parse.urlencode(form_data),'utf-8')
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0'}
        url="http://s.weibo.com/ajax/mblog/forward?__rnd=1516557266248"
        req = urllib2.Request(
            url=url,
            data=formData
        )
        req.add_header('X-Requested-With','XMLHttpRequest')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        req.add_header('Origin', 'http://s.weibo.com')
        req.add_header('Referer', url)
        print("转发操作...")
        result = urllib2.urlopen(req)
        print(result.read().decode('utf-8'))

    def follow(self,uid):
        form_data = {
            "type": "followed",
            "uid": uid,
            "f": 1,
            # "extra":"refer_flag:0000020001_|refer_lflag:1001030103_|loca:|refer_sort:",
            "refer_sort":"card",
            # "refer_flag": "0000020001_",
            "location":"",
            "oid":"",
            "wforce": 1,
            "nogroup": "false",
            "_t": 0
        }
        formData = bytes(urllib.parse.urlencode(form_data),'utf-8')
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0'}
        url="http://s.weibo.com/ajax/user/follow?__rnd=1516592321773"
        req = urllib2.Request(
            url=url,
            data=formData
        )
        req.add_header('X-Requested-With','XMLHttpRequest')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        req.add_header('Origin', 'http://s.weibo.com')
        req.add_header('Referer', url)
        print("关注操作...")
        result = urllib2.urlopen(req)
        print(result.read().decode('utf-8'))
    #抓取微博id和用户id
    def getMidAndUid(self,html):
         mids=[]
         uids=[]
         p = re.compile('(uid=.*&)')
         soup = BeautifulSoup(html)
         uls = soup.find_all("ul",class_="feed_action_row4")
         for ul in uls:
             as_ = ul.find_all("a",attrs={"action-type":"feed_list_forward"})
             if len(as_)>0:
              action = as_[0].attrs["action-data"]
              params = action.split("&")
              for param in params:
                 if param.find("mid=")>=0:
                     mids.append(param.replace("mid=",""))
                 if param.find("uid=")>=0:
                     uids.append(param.replace("uid=",""))
         return mids,uids
    #发送转发微博
    def forwardWb(self,keyWord):
        #url = 'http://s.weibo.com/weibo/%E6%8A%BD%E5%A5%96?topnav=1&wvr=6&b=1'
        keyWord = urllib.parse.quote(keyWord)
        url="http://s.weibo.com/weibo/"+keyWord+"?topnav=1&wvr=6&b=1"
        request = urllib2.Request(url)
        response = urllib2.urlopen(request)
        text = response.read().decode('utf-8')
        p = re.compile('.*STK\.pageletM\.view\((.*)\)</script>.*')
        list = p.findall(text)
        for json_data in list:
            data = json.loads(json_data)
            mids,uids = self.getMidAndUid(data['html'])
            for mid in mids:
                if mid not in self.lastWids:
                 self.foward(mid)
                 time.sleep(200)
            self.lastWids = mids
            for uid in uids:
                if mid not in self.lastUids:
                 self.follow(uid)
                 time.sleep(200)
            self.lastUids = uids
def execFoward(isTime):
    if isTime == "y":
        while True:
            try:
                weiboFoward.forwardWb(keyword)
                time.sleep(time_)
            except Exception as e:
                print("出错了")
                print(e)
    elif isTime == "n":
        weiboFoward.forwardWb(keyword)
    else:
        isTime = input("请输入y或n:")
        execFoward(isTime)

weiboFoward = weiboFoward()
cf = configparser.ConfigParser()
cf.read("config.conf",encoding="utf-8-sig")
username = cf.get("base","username")
password = cf.get("base","password")
keyword  = cf.get("base","keyword")
time_ = int(cf.get("base","time"))*60
isTime = input("是否定时执行？（y/n）:")
weiboFoward.login(username, password)
execFoward(isTime)

