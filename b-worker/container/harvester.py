#!/usr/bin/env python3
# coding=utf-8
#
# This file is part of b-swarm
# Licensed under the GNU General Public License version 3 (GPLv3)
#
# Author: BB, 2024
# __version__ = "code_version/report_syntax_version"
__license__ = "gplv3"
__author__ = "bb"
__version__ = "0.34/0.52"

# TODO:
# 1. Add session handover between Selenium and Requests. Or acquire the
# HTTP headers via Socket;
# 2. Detect malicious file download url - no snapshot for those. Check if
# file exists and may be downloaded, but no actual downloads. Later, download 
# and calculate file hashes;
# 3. if the target url is the file, its hash should be calculated and provided
# for future analysis (e.g., VirusTotal API etc.).

import base64
import logging
import subprocess
import ssl
from time import time, sleep
from json import loads
from io import BytesIO
from random import randint
from urllib.parse import urlparse
from hashlib import sha256
from uuid import uuid1
from os import environ
from datetime import datetime, timedelta
from math import log2
from collections import Counter

import ppdeep
import requests
from PIL import Image
from pyvirtualdisplay.display import Display
from google.cloud import storage
import pandas as pd

from selenium import webdriver
from selenium.webdriver.support.wait import WebDriverWait


def logger(logFile):
    """
    Initialize and start the logging
    """
    logging.basicConfig(
        filename=logFile,
        encoding='utf-8',
        level=logging.DEBUG
        )
    log = logging.getLogger(__name__)
    return log

def get_sha256(data_source):
    """
    Calculate the SHA256 hash for the provided content.
    """
    log.info("Calculating SHA256")
    try:
        data_source = data_source.encode('utf-8')
    except:
        pass
    contentSha256 = sha256(data_source).hexdigest()
    return contentSha256

def get_ppdeep(data_source):
    """
    Calculate ppdeep fuzzy-hash for the provided content
    """
    log.info("Calculating fuzzy-hash")
    contentPpdeep = ppdeep.hash(data_source)
    return contentPpdeep

def get_entropy(data_source):
    """
    Calculate the Shannon entorpy for the provided content.
    """
    log.info("Calculating Shannon entropy")
    counter = Counter(data_source)
    length = float(len(data_source))
    ent = -sum(
        count / length * log2(count / length)
        for count in counter.values()
        )
    return ent

def get_random_useragent():
    """
    Sets the user-agent variable based on the profile specification.
    If no user-agent is specified, set it to a random valid user-agent
    """
    with open("user-agents.txt", 'r') as file:
        useragents = file.readlines()
    userAgent = useragents[
        randint(0, len(useragents) - 1)
    ]
    log.debug(f"User agent: {userAgent}")
    return userAgent

def check_url(url):
    """
    Verifies and modifies the URL into a fully qualified.
    Assumes HTTPS as a default schema.
    """
    origUrl = url
    if not urlparse(url).scheme:
        url = "https://" + url
    log.debug(f"Checking URL {origUrl} -> {url}") 
    return url

def get_content_type(url):
    """
    Try to identify what is the content type of the target url.
    Needed to distinguish between the URLs serving text/html and the ones
    serving files.
    """
    try:
        log.info("Detecting URL content-type")
        requests.head(url).headers["Content-Type"]
    except Exception as err:
        return False

def start_display(horizontalSize, verticalSize, backend="xvfb"):
    """
    Starts a virtual display for headless browser sessions
    """
    display = Display(
        visible=False,
        size=(
            horizontalSize,
            verticalSize
            ),
        backend=backend
        )
    display.start()
    log.info(f"{backend} display started")
    return display

def stop_display(display):
    """
    Closes a virtual display used for headless browser session
    """
    if display:
        display.stop()
    log.info("Dsplay stopped")

def get_selenium_driver(userAgent, horizontalSize, verticalSize):
    """
    Initializes the Selenium driver, browser, and its options.
    
    Important Selenium webdriver options:
    Sets the Selenium webdriver page_load_strategy to "normal", which waits
    until all elements are loaded and document "complete" status is received.
    Additional options include:
    "eager" - DOM ready, but other resources may be still loading;
    "none" - Does not wait until resources are loaded.

    Important Chromium options:
     --headlesss for running without GUI from CLI
     --no-sandbox for disabling advanced features, minimize memory consumption
        and avoid webpage saboxing
     --disable-dev-shm-usage to disable /dev/shm usage on Dockerized
        environment, where /dev/shm is too small and results in Chrome,
        pages, or its tabs crashing
    --webview-disable-safebrowsing-support disables Google Safe Browsing to
        permit access to known compromised web resources
    Additional flags, whcih may potentially improve the operation or access
    to the URLs is under Testing flag, which may be enabled or disabled.
    """
    log.info("Initializing Selenium browser")
    chromePath = "/usr/bin/chromium"
    options = webdriver.ChromeOptions()
    options.binary_location = chromePath
    options.page_load_strategy = "normal"
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument(f"--user-agent={userAgent}")
    testing = True
    if testing:
        options.add_argument("--disable-extensions")
        options.add_argument("--disable-gpu")
        options.add_argument("--start-maximized")
        options.add_argument("--webview-disable-safebrowsing-support")
    if harvestPrivatemode:
        options.add_argument("--incognito")
        log.info("Browser private mode set")
    if proxySettings:
        log.info(f"Setting proxy to {proxySettings}")
        options.add_argument(f"--proxy-server={proxySettings}")
    try:
        driver = webdriver.Chrome(
            options=options
            )
        driver.set_window_size(
            horizontalSize,
            verticalSize
            )
        if requestTimeout:
            log.info(f"Setting request timeout to {requestTimeout}")
            driver.set_page_load_timeout(requestTimeout)
    except Exception as err:
        log.error(f"Browser initialization error: {err}")
        return False
    else:
        log.info("Selenium browser initialized")
        return driver

def wait_loading(driver, timeout=15): # Deprecate?
    """
    Wait for the page to load.
    """
    log.info("Browser wait for page to load")
    wait = WebDriverWait(driver, timeout)
    wait.until(
        lambda driver: driver.execute_script
            ('return document.readyState') == 'complete'
        )

def convert_image_grayscale(pngImage):
    """
    Convert the color PNG image to grayscale PNG image
    """
    image = Image.open(BytesIO(pngImage))
    grayscaleImage = image.convert("L")
    bytesArray = BytesIO()
    grayscaleImage.save(bytesArray, format="PNG")
    return bytesArray.getvalue()

def close_selenium_driver(driver):
    """
    Close the Selenium driver.
    Return True if driver is closed or no drivers exist.
    Return False if an exception was encountered
    """
    try:
        driver.close()
        driver.quit()
        driver.service.stop()
        log.info("Closed Selenium browser")
        return True
    except Exception as err:
        log.error(err)
        return False

def get_ssl_fingerprint(url):
    """
    Exctract target website SSL certificate fingerprint
    """
    log.info("Retrieving SSL certificate fingerprint")
    domain = urlparse(url).netloc
    try:
        sslConnection = ssl.create_connection((domain, 443))
        sslContext = ssl.create_default_context()
        sslData = sslContext.wrap_socket(
            sslConnection,
            server_hostname=domain
            )
        bindata = sslData.getpeercert(True) 
        fingerprint = get_sha256(bindata)
        sslConnection.close()
        return fingerprint
    except Exception as err:
        log.error(err)
        return ""

def get_selenium_content(driver, targetUrl):
    """
    Capture the website graphical image in base64 format.
    Returns False, if an Exception has been encoutnered.
    Returns a tuple of (HTML, Cookies, WebImage) if page is reachable.

    """
    log.info("Acquiring content via Selenium browser")
    try:
        driver.get(targetUrl)
        # wait_loading(driver) # Instead, wses Selenium `page_load_stragegy`
        currentUrl = driver.current_url
    except Exception as err:
        log.error(f"Browser content load error: {err}")
        return False
    else:
        if contentHtml:
            log.info("Retrieving page source and session cookies")
            try:
                targetHtml = driver.page_source
                targetCookies = driver.get_cookies()
            except Exception as err:
                log.error(err)
                targetHtml, targetCookies = ("",) * 2
        else:
            targetHtml = ""
            targetCookies = ""
        if contentImage:
            log.info("Collecting page screenshot")
            try:
                targetImageBin = driver.get_screenshot_as_png()
            except Exception as err:
                log.error(err)
                targetImageBin = b""
        else:
            targetImageBin = b""
        if harvestHeaders:
            targetHeaders = "" # TODO: Collect headers
        else:
            targetHeaders = ""
        return (
                targetHtml,
                targetCookies,
                targetImageBin,
                currentUrl,
                targetHeaders
        )

def save_report(reportFile):
    """
    Convert and save the final session report
    """
    dataFrame = pd.DataFrame(sessionReport)
    dataFrame = dataFrame.astype(pandasSchema)
    dataFrame.to_parquet(reportFile,
                         engine="fastparquet",
                         index=False,
                         compression="snappy")

def load_profile(jsonFile):
    """
    Open and load the JSON profile file.
    The future approach is to deliver the configruation profile via
    the messaging queue (e.g., Nats), instead of files.
    """
    log.info("Loading JSON profile")
    with open(jsonFile) as f:
        jsonData = f.read()
    jsonProfile = loads(jsonData)
    metaProfile = jsonProfile["profile_meta"]
    managerProfile = jsonProfile["manager"]
    connectorProfile = jsonProfile["connector"]
    harvesterProfile = jsonProfile["harvester"]
    reporterProfile = jsonProfile["reporter"] # To be used for Message queues
    global profileId
    profileId = metaProfile["profile_id"]
    global profileTimestamp
    profileTimestamp = metaProfile["timestamp"]
    global taskId
    taskId = managerProfile["task_id"]
    global taskCount
    taskCount = managerProfile["task_count"]
    global taskSleep
    taskSleep = managerProfile["task_sleep"]
    global connectorIpRegion
    connectorIpRegion = connectorProfile["ip_region"]
    global connectorProxy
    connectorProxy = connectorProfile["proxy"]
    global connectorTor
    connectorTor = connectorProfile["tor"]
    global harvestUrl
    harvestUrl = harvesterProfile["harvest_url"]
    for url in harvestUrl:
        urlList.append(
            check_url(url)
        )
    global harvestUseragent
    harvestUseragent = harvesterProfile["harvest_useragent"]
    if not harvestUseragent:
        harvestUseragent = get_random_useragent()
    global harvestPrivatemode
    harvestPrivatemode = harvesterProfile["harvest_privatemode"]
    global harvestHeaders
    harvestHeaders = harvesterProfile["harvest_headers"]
    global harvestTime
    harvestTime = harvesterProfile["harvest_timer"]
    global requestTimeout
    requestTimeout = harvesterProfile["harvest_requesttimeout"]
    global harvestTimeout # overall harvest timeout not implemented
    harvestTimeout = harvesterProfile["harvest_timeout"]
    global contentSsl
    contentSsl = harvesterProfile["content_ssl"]
    global contentHtml
    contentHtml = harvesterProfile["content_html"]
    global contentImage
    contentImage = harvesterProfile["content_image"]
    global contentImageSize
    contentImageSize = harvesterProfile["content_imagesize"]
    global contentImageGrayscale
    contentImageGrayscale = harvesterProfile["content_image_grayscale"]
    global contentSha256
    contentSha256 = harvesterProfile["content_sha256"]
    global contentSsdeep
    contentSsdeep = harvesterProfile["content_ssdeep"]
    global contentEntropy
    contentEntropy = harvesterProfile["content_entropy"]
    log.info("Loading JSON profile done")

def create_connection():
    """
    Create the specified network layer connection, based on the
    worker assigned profile
    """
    global agentConnection
    agentConnection = ""
    global proxySettings
    proxySettings = ""
    if connectorProxy:
        agentConnection = "PROXY"
        proxySettings = connectorProxy
    elif connectorTor:
        agentConnection = "TOR"
        global torService
        torService = start_tor()
        if torService:
            proxySettings = "socks5://127.0.0.1:9050"
        else:
            proxySettings = ""
    else:
        agentConnection = "IPNET"

def start_tor():
    """
    Launch and wait until Tor process starts
    """
    log.info("Starting Tor process")
    torProcess = subprocess.Popen(
        ["tor"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
        )
    log.info("Waiting for Tor process to bootstrap")
    while True:
        torStdout = torProcess.stdout.readline()
        if not torStdout and torProcess.poll() is not None:
            log.error("Tor process failed")
            return False
        if torStdout:
            if "Bootstrapped 100% (done)" in torStdout:
                log.info("Tor process started")
                return torProcess

def stop_tor(torProcess):
    """
    Terminate the Tor process
    """
    log.info("Terminating Tor process")
    torProcess.stdout.close()
    torProcess.stderr.close()
    torProcess.terminate()
    torProcess.wait()
    status = torProcess.poll()
    log.info(f"Tor termination status {status}")

def get_agent_id():
    """
    Create a unique worker ID based on deployed region, connection type,
    data collection profileID, and taskID
    """
    nodeID = str(uuid1())
    nodeIDshort = nodeID.split('-')[0]
    agentID = (f"{nodeID}:{connectorIpRegion}:{agentConnection}:"
               f"{profileId}:{taskId}")
    return (agentID, nodeIDshort)

def snapshot(url, virtualDisplay=True):
    """
    Collect the target URL data and create a snapshot
    """
    display = None
    if virtualDisplay:
        display = start_display(
            contentImageSize[0],
            contentImageSize[1]
            )
    browser = get_selenium_driver(
        harvestUseragent,
        contentImageSize[0],
        contentImageSize[1]
        )
    if harvestTime:
        startTime = time()
    else:
        startTime = 0
    if browser:
        response = get_selenium_content(
            browser,
            url
            )
    else:
        response = (
            "",
            {},
            b"",
            "",
            ""
        )
    if contentSsl:
        sslFingerprint = get_ssl_fingerprint(url)
    else:
        sslFingerprint = ""
    if harvestTime:
        endTime = time()
    else:
        endTime = 0
    if browser:
        close_selenium_driver(browser)
    if virtualDisplay:
        stop_display(display)
    if response:
        content = response[0]
        cookies = response[1]
        image = response[2]
        curl = response[3]
        headers = response[4]
    else:
        content, cookies, image, curl, headers = (
            "",
            {},
            b"",
            "",
            ""
        )
    if content and contentSha256:
        hashSha256 = get_sha256(content)
    else:
        hashSha256 = ""
    if content and contentSsdeep:
        hashPpdeep = get_ppdeep(content)
    else:
        hashPpdeep = ""
    if content and contentEntropy:
        entropy = get_entropy(content)
    else:
        entropy = 0
    if contentImageGrayscale and image:
        image = convert_image_grayscale(image)
    interactReport = {
        "meta_version": __version__.split('/')[1],
        "meta_taskid": taskName,
        "meta_agentid": workerId[0],
        "meta_timestamp": datetime.fromtimestamp(time()),
        "meta_starttime": datetime.fromtimestamp(startTime),
        "meta_endtime": datetime.fromtimestamp(endTime),
        "meta_interacttime": timedelta(seconds=(endTime - startTime)), # Consider storing as float64
        "url_init": url,
        "url_end": curl,
        "http_useragent": harvestUseragent,
        "http_ssl": sslFingerprint,
        "http_headers": headers,
        "http_cookies": str(cookies),
        "http_content": content,
        "http_sha256": hashSha256,
        "http_fuzzyhash": hashPpdeep,
        "http_entropy": entropy,
        "http_image": image
    }
    sessionReport.append(interactReport)

def google_bucket_auth(bucketName=None, serviceKey=None):
    """
    Authenticate against Google Cloud Services and access the specified
    storage bucket, where agent profile is located and worker reports
    will be stored.
    To increase security, the authentication data is stored as environment
    variables and not as a file on a filesystem. This is not a complete
    security, since the key is anyway in the memory.
    To retain special characters in the key, it is base64 encoded.
    """
    if serviceKey:
        client = storage.Client.from_service_account_json(serviceKey)
    else:
        bucketName = environ.get("BUCKET")
        serviceEmail = environ.get("SERVICE_EMAIL")
        serviceKeyB64 = environ.get("SERVICE_KEY_B64").encode("utf8")
        serviceKey = base64.b64decode(serviceKeyB64).decode('utf8')
        serviceProject = environ.get("SERVICE_PROJECT")
        serviceAccount = {
            "type": "service_account",
            "token_uri": "https://oauth2.googleapis.com/token",
            "private_key": serviceKey,
            "client_email": serviceEmail,
            "project_id": serviceProject
            }
        client = storage.Client.from_service_account_info(serviceAccount)
    bucket = client.get_bucket(bucketName)
    return bucket

def google_bucket_upload(bucket, sourceFile, destinationFile):
    """
    Use Google cloud storage API to access bucket and upload a file
    """
    blob = bucket.blob(destinationFile)
    blob.upload_from_filename(sourceFile)

def google_bucket_download(bucket, sourceFile, destinationFile):
    """
    Use Google cloud storage API to access bucket and download a file
    """
    blob = bucket.blob(sourceFile)
    blob.download_to_filename(destinationFile)


# GLOBAL variables
urlList = []
sessionReport = []
pandasSchema = {
    "meta_version": "string",
    "meta_taskid": "string",
    "meta_agentid": "string",
    "meta_timestamp": "datetime64[ms]",
    "meta_starttime": "datetime64[ms]",
    "meta_endtime": "datetime64[ms]",
    "meta_interacttime": "timedelta64[ms]", # consider float64
    "url_init": "string",
    "url_end": "string",
    "http_useragent": "string",
    "http_ssl": "string",
    "http_headers": "string",
    "http_cookies": "string",
    "http_content": "string",
    "http_sha256": "string",
    "http_fuzzyhash": "string",
    "http_entropy": "float64",
    "http_image": "object"
}

if __name__ == "__main__":
    log = logger("log/harvester.log")
    authBucket = google_bucket_auth()
    google_bucket_download(
        authBucket,
        "profile.json",
        "profile.json"
        )
    load_profile("profile.json")
    torService = None
    create_connection()
    workerId = get_agent_id()
    cycle = 1
    while cycle <= taskCount:
        log.info(f"Session cycle:{cycle}/{taskCount}")
        taskName = f"{taskId}-{cycle}-{workerId[1]}"
        for url in urlList:
            log.debug(f"Harvesting {url} from {urlList}")
            snapshot(url)
        save_report(f"rep/report_{taskName}.parquet")
        google_bucket_upload(
            authBucket,
            f"rep/report_{taskName}.parquet",
            f"report_{taskName}.parquet"
            )
        del sessionReport
        cycle += 1
        sleep(taskSleep)
    if torService:
        stop_tor(torService)
    log.info("QUIT")
    quit(0)