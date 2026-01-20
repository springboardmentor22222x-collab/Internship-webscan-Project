# alternative fetch using selenium
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

def fetch_with_selenium(url, driver_path="chromedriver"):
    opts = Options()
    opts.add_argument("--headless")
    driver = webdriver.Chrome(executable_path=driver_path, options=opts)
    try:
        driver.get(url)
        html = driver.page_source
        status = 200
        return status, html
    except Exception as e:
        print(f"[selenium fetch] error: {e}")
        return None, None
    finally:
        driver.quit()
