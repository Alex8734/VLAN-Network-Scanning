import sys
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities

# Set up Chrome options
chrome_options = Options()
chrome_options.add_argument("--headless=new")
chrome_options.add_argument("--no-sandbox")
chrome_options.add_argument("--disable-dev-shm-usage")

chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3")

# Attempt to suppress all logs (this might not be fully effective for DevTools logs)
chrome_options.add_argument("--log-level=3")
service = Service(ChromeDriverManager().install(),log_output="chromedriver.log")
 
driver = webdriver.Chrome(service=service, options=chrome_options)

driver.get("http://192.168.116.156/")

time.sleep(.5)
title = driver.title
driver.quit()

print(title)