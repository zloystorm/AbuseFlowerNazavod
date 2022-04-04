import email
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from email.header import decode_header
from email.message import Message
from random import randint

import names
import requests as r
import socks
from bson import ObjectId
from loguru import logger
from pymongo import MongoClient
from pyuseragents import random as random_useragent
from twocaptcha import TwoCaptcha

from abuseFlower.utils.SslImap import Imap4SslProxy

mailServerIMAP = "IMAPSERVER"
mailServerPort = 993

apiCaptchaToken = "CAPTCHATOKEN TwoCapthca RuCatpcha"

dbMongoConnectLink = os.environ["CryptoBotsMongoDb"]
dbClient = MongoClient(dbMongoConnectLink)
dataBase = dbClient['Abuse']
flowerDb = dataBase["Flower"]


def get_tor_session():
    session = r.session()
    login = str(randint(1, 0x7fffffff))
    pwd = str(randint(1, 0x7fffffff))
    session.proxies = {'http': f'socks5://{login}:{pwd}@127.0.0.1:9050',
                       'https': f'socks5://{login}:{pwd}@127.0.0.1:9050'}
    proxyData = {
        "login": str(randint(1, 0x7fffffff)),
        "pass": str(randint(1, 0x7fffffff))
    }
    return session, proxyData


def getCodeFromEmail(login, pwd, proxyData):
    connection = Imap4SslProxy(host=mailServerIMAP,
                               port=mailServerPort,
                               p_proxy_port=9050,
                               p_proxy_addr="127.0.0.1",
                               p_timeout=10,
                               p_proxy_username=proxyData["login"],
                               p_proxy_password=proxyData["pass"],
                               p_proxy_type=socks.SOCKS5)
    connection.login(login, pwd)
    link = ""
    findedLink = False
    counter = 0
    while not findedLink:
        counter = counter + 1
        if counter > 10:
            raise Exception("Сообщение не пришло")
        status, countMessagesB = connection.select("inbox")
        countMessages = int(countMessagesB[0])
        if countMessages == 0:
            time.sleep(10)
            status, countMessagesB = connection.select("Spam")
            countMessages = int(countMessagesB[0])
            if countMessages == 0:
                continue
        logger.info(f"Ждем сообщение {login}")
        for i in range(countMessages, countMessages - 1, -1):
            status, msgRaw = connection.fetch(str(i), "(RFC822)")
            msg: Message = email.message_from_bytes(msgRaw[0][1])
            if decode_header(msg["From"])[0][0] == "tonari-no-news@kaikaikiki.co.jp":
                logger.info("Получили сообщение")
                body = msg.get_payload(decode=True).decode()
                link = re.findall("(https://[\S\w\W=]*)<Note>", body, re.RegexFlag.MULTILINE)
                if link[0] is not None:
                    findedLink = True
                    link = str(link[0]).replace("\n", "")
                    link = str(link).replace("\r", "")
                if findedLink:
                    break
        if findedLink == False:
            status, countMessagesB = connection.select("Spam")
            countMessages = int(countMessagesB[0])
            if countMessages == 0:
                time.sleep(10)
                continue
            for i in range(countMessages, countMessages - 1, -1):
                status, msgRaw = connection.fetch(str(i), "(RFC822)")
                msg: Message = email.message_from_bytes(msgRaw[0][1])
                if decode_header(msg["From"])[0][0] == "tonari-no-news@kaikaikiki.co.jp":
                    logger.info("Получили сообщение")
                    body = msg.get_payload(decode=True).decode()
                    link = re.findall("(https://[\S\w\W=]*)<Note>", body, re.RegexFlag.MULTILINE)
                    if link[0] is not None:
                        findedLink = True
                        link = str(link[0]).replace("\n", "")
                        link = str(link).replace("\r", "")
                    if findedLink:
                        break
        time.sleep(10)
    logger.info(f"Вернули рег линк {link}")
    return link


def loop():
    running = True
    while running:
        mail = flowerDb.find_one_and_update({
            "used": False,
        },
            {
                "$set": {
                    "used": True
                }
            }
        )
        if mail is None:
            return
        try:
            login = mail["login"]
            pwd = mail["pass"]
            wallet = mail["wallet"]
            sendFirstTime(login, pwd, wallet)
            flowerDb.update_one(
                {
                    "_id": ObjectId(str(mail["_id"]))
                },
                {
                    "$set": {
                        "error": False,
                        "complete": True
                    }
                }
            )
        except Exception as e:
            logger.error(e)
            flowerDb.update_one(
                {
                    "_id": ObjectId(str(mail["_id"]))
                },
                {
                    "$set": {
                        "error": True,
                        "complete": False
                    }
                }
            )


def checkMail(login, pwd, proxyData):
    try:
        connection = Imap4SslProxy(host=mailServerIMAP,
                                   port=mailServerPort,
                                   p_proxy_port=9050,
                                   p_proxy_addr="127.0.0.1",
                                   p_timeout=10,
                                   p_proxy_username=proxyData["login"],
                                   p_proxy_password=proxyData["pass"],
                                   p_proxy_type=socks.SOCKS5)
        connection.login(login, pwd)
    except Exception as e:
        raise Exception("Почты с %")


def sendFirstTime(login, pwd, wallet):
    logger.info(f"Получили данные {login} {pwd} {wallet}")
    sender, proxyData = get_tor_session()

    checkMail(login, pwd, proxyData)

    userAgent = random_useragent()
    sender.headers.update({
        'user-agent': userAgent, 'accept': '*/*', 'accept-language': 'ru,en;q=0.9,vi;q=0.8,es;q=0.7',
        'referer': 'https://murakamiflowers.kaikaikiki.com/',
        "origin": "https://murakamiflowers.kaikaikiki.com"
    }
    )
    tt = sender.get(
        "https://murakamiflowers.kaikaikiki.com/register/new"
    )
    tokenCSRF = re.findall(".*name=\"csrf-token\" content=\"([\w-]*)\".*", tt.text, re.RegexFlag.MULTILINE)
    tokenCSRF = tokenCSRF[0]
    sender.headers.update(
        {
            'x-csrf-token': tokenCSRF
        }
    )
    siteRe = re.findall(".*<div data-sitekey=\"([\w-]*)\".*", tt.text)
    siteKey = siteRe[0]
    hiddenRe = re.findall(".*<input type=\"hidden\" name=\"authenticity_token\" value=\"([\w+=-]*)\".*", tt.text)
    hiddenToken = hiddenRe[0]
    cookies = ""
    for item in sender.cookies.items():
        key, value = item
        cookies = cookies + f"{key}:{value};"
    solver = TwoCaptcha(apiCaptchaToken)
    logger.info("Решаем капчу")
    resultCaptcha = solver.recaptcha(
        sitekey=siteKey,
        url='https://murakamiflowers.kaikaikiki.com/',
        userAgent=userAgent,
        invisible=0,
        cookies=cookies
    )
    tokenCaptcha = resultCaptcha["code"]
    dataPost = sender.post(
        "https://murakamiflowers.kaikaikiki.com/register/new_account",
        data={
            "authenticity_token": hiddenToken,
            "t": "new",
            "email": login,
            "g-recaptcha-response": tokenCaptcha,
            "commit": "SEND REGISTRATION MAIL"
        },
        headers={
            'User-Agent': userAgent,
            'x-csrf-token': tokenCSRF,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-origin",
            "sec-fetch-user": "?1",
            "referrer": "https://murakamiflowers.kaikaikiki.com/register/new",
            "referrerPolicy": "strict-origin-when-cross-origin",
        }
    )
    logger.info("Отправили запрос на линк")
    time.sleep(10)
    link = getCodeFromEmail(login, pwd, proxyData)
    if link == "https://murakamiflowers.kaikaikiki.com/register/":
        return
    registerAgain(login, pwd, wallet, link, userAgent, sender)


def registerAgain(login, pwd, wallet, link, userAgent, sender):
    logger.info("Проходим регистрацию 2 этап")
    name = names.get_full_name()
    logger.info(f"Получили имя {name}")

    parseT = link.split("https://murakamiflowers.kaikaikiki.com/register/register?t=")[1].split("&")[0]
    parseU = link.split("https://murakamiflowers.kaikaikiki.com/register/register?t=")[1].split("&")[1].split("=")[1]

    tt = sender.get(
        url="https://murakamiflowers.kaikaikiki.com/register/register",
        params={
            "t": parseT,
            "u": parseU
        },
        allow_redirects=True,
    )

    tokenCSRF = re.findall(".*name=\"csrf-token\" content=\"([\w-]*)\".*", tt.text, re.RegexFlag.MULTILINE)
    tokenCSRF = tokenCSRF[0]

    siteRe = re.findall(".*<div data-sitekey=\"([\w-]*)\".*", tt.text)
    siteKey = siteRe[0]

    hiddenRe = re.findall(".*<input type=\"hidden\" name=\"authenticity_token\" value=\"([\w=+_-]*)\".*", tt.text)
    hiddenToken = hiddenRe[0]

    cookies = ""
    for item in sender.cookies.items():
        key, value = item
        cookies = cookies + f"{key}:{value};"

    solver = TwoCaptcha(apiCaptchaToken)
    logger.info("Решаем капчу 2 раз")
    resultCaptcha = solver.recaptcha(
        sitekey=siteKey,
        url='https://murakamiflowers.kaikaikiki.com/',
        userAgent=userAgent,
        invisible=0,
        cookies=cookies
    )
    tokenCaptcha = resultCaptcha["code"]

    time.sleep(randint(3, 6))
    resp = sender.post(
        "https://murakamiflowers.kaikaikiki.com/register/register",
        data={
            "authenticity_token": str(hiddenToken),
            "user[email]": str(login).lower(),
            "user[name]": str(name),
            "user[metamask_wallet_address]": str(wallet),
            "user[password]": str(pwd),
            "user[password_confirmation]": str(pwd),
            "g-recaptcha-response": str(tokenCaptcha),
            "t": str(parseT),
            "u": str(parseU),
            "commit": "Confirm"
        }, allow_redirects=True,
        headers={
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "accept-language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
            "cache-control": "max-age=0",
            "content-type": "application/x-www-form-urlencoded",
            "sec-ch-ua": "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"99\", \"Google Chrome\";v=\"99\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-origin",
            "sec-fetch-user": "?1",
            "upgrade-insecure-requests": "1",
            "referrer": link,
            "referrerPolicy": "strict-origin-when-cross-origin",
            "credentials": "include",
            "mode": "cors",
            "Host": "murakamiflowers.kaikaikiki.com"
        }
    )
    logger.info(f"Аккаунт зареган\n Login: {login} Pass: {pwd}")


def start():
    logger.info("Start")
    countThreads = 50
    with ThreadPoolExecutor(countThreads) as executor:
        for _ in range(countThreads):
            executor.submit(loop)
            time.sleep(2)


if __name__ == "__main__":
    start()
