from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from datetime import datetime
import os

def capture_screenshot(driver, url, screenshot_dir):
  """Captures a screenshot of the current webpage.

  Args:
      driver (webdriver.Chrome): The Selenium WebDriver instance.
      url (str): The URL of the webpage to capture.
      screenshot_dir (str): The directory to save the screenshot.
  """

  try:
    driver.get(url)

    # Wait for the page to load completely (optional)
    # WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, "your_unique_element_id")))  

    # Generate a unique filename based on timestamp
    now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = screenshot_dir + "/" + now + ".png"

    driver.save_screenshot(filename)
    print(f"Screenshot captured: {filename}")
  except Exception as e:
    print(f"Error capturing screenshot of {url}: {e}")

def main():
  """Main function to iterate through a list of URLs and capture screenshots."""

  
  urls = []
  
  with open('urls.txt', 'r') as file:
    for line in file:
        urls.append(line.strip())
        
  screenshot_dir = "/home/diego/sniffer"  # Replace with your desired directory

  # Initialize the WebDriver 
  
  options = webdriver.ChromeOptions()
  options.add_argument("--headless")  # headless mode
  options.add_argument("--no-sandbox")
  options.add_argument("--disable-dev-shm-usage")
  
  driver = webdriver.Chrome(options=options)
	
  for url in urls:
    capture_screenshot(driver, url, screenshot_dir)

  # Quit the WebDriver (optional)
  driver.quit()

if __name__ == "__main__":
  main()
